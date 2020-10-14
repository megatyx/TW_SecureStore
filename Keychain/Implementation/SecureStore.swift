//
//  SecureStore.swift
//  Created by Tyler Wells
//

import Security
import Foundation

// MARK: Query

private struct KeychainSearchQuery {
    enum GenerateQueryPurpose {
        case set
        case get
        case update
        case delete
    }
    
    let service: String = "\(KeychainSecConstants.baseSecureServiceName).keychain"
    var clz: KeychainSecurityClass
    var attrAccount: String
    var valueData: Data?
    var matchLimit: KeychainMatch?
    var returnData: KeychainReturnData?
    var accessOption: KeychainAccessOptions?
    
    init(clz: KeychainSecurityClass = .genericPassword, attrAccount: String, valueData: Data? = nil, purpose: GenerateQueryPurpose) {
        self.clz = clz
        self.attrAccount = attrAccount
        
        switch purpose {
        case .get:
            self.matchLimit = .matchLimitOne
            self.returnData = .yes
        case .set:
            self.valueData = valueData
        case .update:
            self.valueData = valueData
        case .delete:
            break
        }
    }
}

private extension KeychainSearchQuery {
    var query: CFDictionary {
        var result: [String : Any] = [ KeychainSecConstants.clz : clz.rawValue,
                                       KeychainSecConstants.attrAccount : attrAccount,
                                       KeychainSecConstants.service: service ]
        
        if let returnData = returnData {
            result[KeychainSecConstants.returnData] = returnData.rawValue
        }
        
        if let matchLimit = matchLimit {
            result[KeychainSecConstants.matchLimit] = matchLimit.rawValue
        }
        
        if let valueData = valueData {
            result[KeychainSecConstants.valueData] = valueData
        }
        
        if let accessOption = accessOption {
            result[KeychainSecConstants.accessible] = accessOption
        }
        
        return result as CFDictionary
    }
    
    var updateAttributes: CFDictionary {
        var result = [String: Any]()
        
        if let valueData = valueData {
            result[KeychainSecConstants.valueData] = valueData
        }
        
        return result as CFDictionary
    }
}

// MARK: - SecureStore

class SecureStore {
    private enum SecureStoreTaskLabel: String {
        case workerQueue
    }
    
    private let workerQueueIdentifier = "\(KeychainSecConstants.baseSecureServiceName).keychain.worker"
    
    private let workerQueue: DispatchQueue
    private let workerQueueKey: DispatchSpecificKey<SecureStoreTaskLabel>
    
    static let shared = SecureStore()
    
    init() {
        workerQueueKey = DispatchSpecificKey<SecureStoreTaskLabel>()
        
        workerQueue = DispatchQueue(label: workerQueueIdentifier)
        workerQueue.setSpecific(key: workerQueueKey, value: SecureStoreTaskLabel.workerQueue)
    }
    
    // MARK: - Private
    
    private func execute(sync: Bool, task: () throws -> Void) rethrows {
        func isWorkerQueue() -> Bool {
            return DispatchQueue.getSpecific(key: workerQueueKey) == SecureStoreTaskLabel.workerQueue
        }
        
        if isWorkerQueue() {
            try task()
        } else {
            try workerQueue.sync {
                try task()
            }
        }
    }
}

// MARK: - Entrance

extension SecureStore {
    private static func _set(data: Data?, key: String, securityClass: KeychainSecurityClass) throws {
        try SecureStore.shared.execute(sync: false) {
            guard let data = data else {
                try SecureStore.shared.executeDelete(with: KeychainSearchQuery(clz: securityClass, attrAccount: key, purpose: .delete))
                
                return
            }
            
            do {
                try _ = _get(from: key, securityClass: securityClass)
                
                try SecureStore.shared.executeUpdate(with: KeychainSearchQuery(clz: securityClass, attrAccount: key, valueData: data, purpose: .update))
                
            } catch KeychainError.secItemNotFound {
                try SecureStore.shared.executeSet(with: KeychainSearchQuery(clz: securityClass, attrAccount: key, valueData: data, purpose: .set))
            } catch {
                throw error
            }
        }
    }
    
    private static func _get(from key: String, securityClass: KeychainSecurityClass) throws -> Data? {
        var result: Data?
        
        try SecureStore.shared.execute(sync: true) {
            result = try SecureStore.shared.executeGet(with: KeychainSearchQuery(clz: securityClass, attrAccount: key, purpose: .get))
        }
        
        return result
    }
}

// MARK: - Execution

extension SecureStore {
    private func executeSet(with searchQuery: KeychainSearchQuery) throws {
        let status = SecItemAdd(searchQuery.query, nil)
        
        if status != noErr {
            throw KeychainError.unhandledKeychainError("set value with query: \(searchQuery) error", status)
        }
    }
    
    private func executeGet(with searchQuery: KeychainSearchQuery) throws -> Data? {
        var data: AnyObject?
        
        let status = SecItemCopyMatching(searchQuery.query, &data)
        
        if status != noErr {
            if status == errSecItemNotFound {
                throw KeychainError.secItemNotFound
            }
            
            throw KeychainError.unhandledKeychainError("get value with query: \(searchQuery) error", status)
        }
        
        return data as? Data
    }
    
    private func executeUpdate(with searchQuery: KeychainSearchQuery) throws {
        let status = SecItemUpdate(searchQuery.query, searchQuery.updateAttributes)
        
        if status != noErr {
            throw KeychainError.unhandledKeychainError("update value with query: \(searchQuery) error", status)
        }
    }
    
    private func executeDelete(with searchQuery: KeychainSearchQuery) throws {
        let status = SecItemDelete(searchQuery.query)
        
        if status != noErr {
            if status == errSecItemNotFound {
                throw KeychainError.secItemNotFound
            }
            
            throw KeychainError.unhandledKeychainError("delete value with query: \(searchQuery) error", status)
        }
    }
}

// MARK: KeychainAccessible

extension SecureStore: KeychainAccessible {
    static func set(object: Data?, on key: String, securtyClass: KeychainSecurityClass) throws {
        try _set(data: object, key: key, securityClass: securtyClass)
    }

    static func get(from key: String, securityClass: KeychainSecurityClass) throws -> Data? {
        return try _get(from: key, securityClass: securityClass)
    }
}
