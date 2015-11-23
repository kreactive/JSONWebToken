//
//  RSASSA_PKCS1.swift
//  JSONWebToken
//
//  Created by Antoine Palazzolo on 18/11/15.
//

import Foundation
import Security

private func paddingForHashFunction(f : SignatureAlgorithm.HashFunction) -> SecPadding {
    switch f {
    case .SHA256:
        return SecPadding.PKCS1SHA256
    case .SHA384:
        return SecPadding.PKCS1SHA384
    case .SHA512:
        return SecPadding.PKCS1SHA512
    }
}

public struct RSASSA_PKCS1Verifier : SignatureValidator {
    let hashFunction : SignatureAlgorithm.HashFunction
    let key : SignatureKey
    
    public init(hashFunction : SignatureAlgorithm.HashFunction, key : SignatureKey) {
        self.hashFunction = hashFunction
        self.key = key
    }
    public func canVerifyWithSignatureAlgorithm(alg : SignatureAlgorithm) -> Bool {
        if case SignatureAlgorithm.RSASSA_PKCS1(self.hashFunction) = alg {
            return true
        }
        return false
    }
    public func verify(input : NSData, signature : NSData) -> Bool {
        let signedDataHash = input.jwt_shaDigestWithSize(self.hashFunction.rawValue)
        let padding = paddingForHashFunction(self.hashFunction)
        
        let result = SecKeyRawVerify(key.value, padding, UnsafePointer<UInt8>(signedDataHash.bytes), signedDataHash.length, UnsafePointer<UInt8>(signature.bytes), signature.length)
        switch result {
        case errSecSuccess:
            return true
        default:
            return false
        }
    }
}

public struct RSASSA_PKCS1Signer : TokenSigner {
    enum Error : ErrorType {
        case CannotAllocateSignatureBuffer
        case SecurityError(OSStatus)
    }
    
    let hashFunction : SignatureAlgorithm.HashFunction
    let key : SignatureKey
    
    public init(hashFunction : SignatureAlgorithm.HashFunction, key : SignatureKey) {
        self.hashFunction = hashFunction
        self.key = key
    }
    
    public var signatureAlgorithm : SignatureAlgorithm {
        return .RSASSA_PKCS1(self.hashFunction)
    }

    public func sign(input : NSData) throws -> NSData {
        let signedDataHash = input.jwt_shaDigestWithSize(self.hashFunction.rawValue)
        let padding = paddingForHashFunction(self.hashFunction)
        
        guard let result = NSMutableData(length: SecKeyGetBlockSize(self.key.value)) else { throw Error.CannotAllocateSignatureBuffer }
        
        var signatureSize = result.length
        let status = SecKeyRawSign(key.value, padding, UnsafePointer<UInt8>(signedDataHash.bytes), signedDataHash.length, UnsafeMutablePointer<UInt8>(result.mutableBytes), &signatureSize)
        
        switch status {
        case errSecSuccess:
            return result.subdataWithRange(NSMakeRange(0, signatureSize))
        default:
            throw Error.SecurityError(status)
        }
    }
}