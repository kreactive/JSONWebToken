//
//  Signature.swift
//  JSONWebToken
//
//  Created by Antoine Palazzolo on 18/11/15.
//  Copyright © 2015 Antoine Palazzolo. All rights reserved.
//

import Foundation


public enum SignatureAlgorithm {
    public enum HashFunction : Int {
        case SHA256 = 256
        case SHA384 = 384
        case SHA512 = 512
        
        private var jwtIdentifierSuffix : String {
            switch self {
            case .SHA256:
                return "256"
            case .SHA384:
                return "384"
            case .SHA512:
                return "512"
            }
        }
    }
    
    case None
    case HMAC(HashFunction) // HMAC
    case RSASSA_PKCS1(HashFunction) // RSASSA-PKCS1-v1_5
    case ECDSA(HashFunction) // ECDSA
    case RSASSA_PSS(HashFunction) //RSASSA-PSS
    
    public init(name : String) throws {
        guard name.characters.count > 0 else {throw JSONWebToken.Error.InvalidSignatureAlgorithm(name)}
        guard name.lowercaseString != "none" else { self = .None; return }
        
        let prefixIndex = name.startIndex.advancedBy(2)
        let prefix = name.substringToIndex(prefixIndex)
        let suffix = name.substringFromIndex(prefixIndex)
        
        let hashFunction : HashFunction = try {
            switch suffix {
            case HashFunction.SHA256.jwtIdentifierSuffix:
                return .SHA256
            case HashFunction.SHA384.jwtIdentifierSuffix:
                return .SHA384
            case HashFunction.SHA512.jwtIdentifierSuffix:
                return .SHA512
            default:
                throw JSONWebToken.Error.InvalidSignatureAlgorithm(name)
            }
            }()
        switch prefix {
        case "HS" : self = .HMAC(hashFunction)
        case "RS" : self = .RSASSA_PKCS1(hashFunction)
        case "ES" : self = .ECDSA(hashFunction)
        case "PS" : self = .RSASSA_PSS(hashFunction)
        default : throw JSONWebToken.Error.InvalidSignatureAlgorithm(name)
        }
    }
    var jwtIdentifier : String {
        switch self {
        case .None:
            return "none"
        case .HMAC(let f):
            return "HS"+f.jwtIdentifierSuffix
        case .RSASSA_PKCS1(let f):
            return "RS"+f.jwtIdentifierSuffix
        case .RSASSA_PSS(let f):
            return "PS"+f.jwtIdentifierSuffix
        case .ECDSA(let f):
            return "ES"+f.jwtIdentifierSuffix
        }
    }
}