//
//  HMAC.swift
//  JSONWebToken
//
//  Created by Antoine Palazzolo on 18/11/15.
//

import Foundation


public struct HMACSignature : SignatureValidator,TokenSigner {
    let secret : NSData
    let hashFunction : SignatureAlgorithm.HashFunction
    
    public func canVerifyWithSignatureAlgorithm(alg : SignatureAlgorithm) -> Bool {
        if case SignatureAlgorithm.HMAC(self.hashFunction) = alg {
            return true
        }
        return false
    }
    public func verify(input : NSData, signature : NSData) -> Bool {
        return input.jwt_hmacSignatureWithSHAHashFuctionSize(self.hashFunction.rawValue, secret: secret) == signature
    }
    
    public var signatureAlgorithm : SignatureAlgorithm {
        return .HMAC(self.hashFunction)
    }
    public func sign(input : NSData) throws -> NSData {
        return input.jwt_hmacSignatureWithSHAHashFuctionSize(self.hashFunction.rawValue, secret: secret)
    }
}