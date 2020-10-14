//
//  KeychainConstants.swift
//  Created by Tyler Wells
//

import Foundation

struct KeychainSecConstants {
    
    /*
     ********************************************************************
     You MUST SET THE FOLLOWING SERVICE NAME TO YOUR LOCAL BUNDLE
     BaseServiceName = "com.{insertBaseHERE}"
     ********************************************************************
     */
    static let baseSecureServiceName = "com."
    
    static var clz: String {
        return stringify(it: kSecClass)
    }
    
    static var attrAccount: String {
        return stringify(it: kSecAttrAccount)
    }
    
    static var returnData: String {
        return stringify(it: kSecReturnData)
    }
    
    static var matchLimit: String {
        return stringify(it: kSecMatchLimit)
    }
    
    static var valueData: String {
        return stringify(it: kSecValueData)
    }
    
    static var accessible: String {
        return stringify(it: kSecAttrAccessible)
    }
    
    static var service: String {
        return stringify(it: kSecAttrService)
    }
    
    private static func stringify(it value: CFString) -> String {
        return value as String
    }
}
