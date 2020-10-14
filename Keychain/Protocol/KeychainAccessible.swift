//
//  KeychainAccessible.swift
//  Created by Tyler Wells
//

import Security
import Foundation

protocol KeychainAccessible {
    static func set(object: Data?, on key: String, securtyClass: KeychainSecurityClass) throws
    static func get(from key: String, securityClass: KeychainSecurityClass) throws -> Data?
}

// MARK: Convenience

extension KeychainAccessible {
    static func set(object: Data?, on key: String) throws {
        try set(object: object, on: key, securtyClass: .genericPassword)
    }
    
    static func get(from key: String) throws -> Data? {
        return try get(from: key, securityClass: .genericPassword)
    }
}

extension KeychainAccessible {
    static func setString(_ string: String, on key: String) throws {
        try set(object: string.data(using: .utf8), on: key)
    }
    
    static func getString(from key: String) throws -> String {
        do {
            if let stringData = try get(from: key), let returnString = String(bytes: stringData, encoding: .utf8)  {
                return returnString
            }
            throw KeychainError.secItemNotFound
        } catch {            
            throw error
        }
    }
    
    static func setBool(_ value: Bool, forKey key: String) throws {
        let bytes: [UInt8] = value ? [1] : [0]
        let data = Data(bytes)
        try set(object: data, on: key)
    }
    
    static func getBool(from key: String) throws -> Bool {
        do {
            guard let data = try get(from: key),
                let firstBit = data.first else { throw KeychainError.nullDataConversion}
            return firstBit == 1
        } catch {
            throw error
        }
    }
}
