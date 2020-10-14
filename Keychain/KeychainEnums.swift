//
//  KeychainEnums.swift
//  Created by Tyler Wells
//

import Security
import Foundation

enum KeychainMatch {
    case matchLimitOne
    case matchLimitAll
}

extension KeychainMatch: RawRepresentable {
    typealias RawValue = CFString
    
    init?(rawValue: CFString) {
        switch rawValue {
        case kSecMatchLimitOne:
            self = .matchLimitOne
        case kSecMatchLimitAll:
            self = .matchLimitAll
        default:
            return nil
        }
    }
    
    var rawValue: CFString {
        switch self {
        case .matchLimitOne:
            return kSecMatchLimitOne
        case .matchLimitAll:
            return kSecMatchLimitAll
        }
    }
}

enum KeychainReturnData {
    case yes
    case no
}

extension KeychainReturnData: RawRepresentable {
    typealias RawValue = CFBoolean
    
    init?(rawValue: CFBoolean) {
        switch rawValue {
        case kCFBooleanTrue:
            self = .yes
        case kCFBooleanFalse:
            self = .no
        default:
            return nil
        }
    }
    
    var rawValue: CFBoolean {
        switch self {
        case .yes:
            return kCFBooleanTrue
        case .no:
            return kCFBooleanFalse
        }
    }
}

enum KeychainSecurityClass {
    case internetPassword
    case genericPassword
    case certificate
    case key
    case identity
}

extension KeychainSecurityClass: RawRepresentable {
    typealias RawValue = CFString
    
    init?(rawValue: CFString) {
        switch rawValue {
        case kSecClassInternetPassword:
            self = .internetPassword
        case kSecClassGenericPassword:
            self = .genericPassword
        case kSecClassCertificate:
            self = .certificate
        case kSecClassKey:
            self = .key
        case kSecClassIdentity:
            self = .identity
        default:
            return nil
        }
    }
    
    var rawValue: CFString {
        switch self {
        case .internetPassword:
            return kSecClassInternetPassword
        case .genericPassword:
            return kSecClassGenericPassword
        case .certificate:
            return kSecClassCertificate
        case .key:
            return kSecClassKey
        case .identity:
            return kSecClassIdentity
        }
    }
}

enum KeychainAccessOptions {
    case whenUnlocked
    case whenUnlockedThisDeviceOnly
    case afterFirstUnlock
    case afterFirstUnlockThisDeviceOnly
    case whenPasscodeSetThisDeviceOnly
}

extension KeychainAccessOptions: RawRepresentable {
    typealias RawValue = CFString
    
    init?(rawValue: CFString) {
        switch rawValue {
        case kSecAttrAccessibleWhenUnlocked:
            self = .whenUnlocked
        case kSecAttrAccessibleWhenUnlockedThisDeviceOnly:
            self = .whenUnlockedThisDeviceOnly
        case kSecAttrAccessibleAfterFirstUnlock:
            self = .afterFirstUnlock
        case kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly:
            self = .afterFirstUnlockThisDeviceOnly
        case kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly:
            self = .whenPasscodeSetThisDeviceOnly
        default:
            return nil
        }
    }
    
    var rawValue: CFString {
        switch self {
        case .whenUnlocked:
            return kSecAttrAccessibleWhenUnlocked
        case .whenUnlockedThisDeviceOnly:
            return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .afterFirstUnlock:
            return kSecAttrAccessibleAfterFirstUnlock
        case .afterFirstUnlockThisDeviceOnly:
            return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        case .whenPasscodeSetThisDeviceOnly:
            return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        }
    }
}

enum KeychainError: Error, Equatable {
    case secItemNotFound
    case dataConvertError(String)
    case unhandledKeychainError(String, OSStatus)
    case nullDataConversion
}
