//
//  SignatureKey.swift
//  JSONWebToken
//
//  Created by Antoine Palazzolo on 19/11/15.
//

import Foundation
import Security

enum SignatureKeyError : ErrorType {
    case SecurityError(OSStatus)
    case PublicKeyNotFoundInCertificate
    case CannotCreateCertificateFromData

}

public struct SignatureKey {
    let value : SecKeyRef
    
    public init(secKey :SecKey) {
        self.value = secKey
    }
    public init(publicKeyFromCertificate cert: SecCertificate) throws {
        var trust : SecTrust? = nil
        let result = SecTrustCreateWithCertificates(cert, nil, &trust)
        if result == errSecSuccess && trust != nil {
            if let publicKey = SecTrustCopyPublicKey(trust!) {
                self.init(secKey : publicKey)
            } else {
                throw SignatureKeyError.PublicKeyNotFoundInCertificate
            }
        } else {
            throw SignatureKeyError.SecurityError(result)
        }
    }
    
    //Creates a certificate object from a DER representation of a certificate
    public init(publicKeyFromCertificateData certData: NSData) throws {
        if let cert = SecCertificateCreateWithData(nil, certData) {
            try self.init(publicKeyFromCertificate : cert)
        }
        throw SignatureKeyError.CannotCreateCertificateFromData
    }
    
    public init(keyData: NSData, tag : String) throws {
        self.value = try SecKeyCreate(keyData: keyData, tag: tag)
    }
    public init(keyModulus : NSData, keyExponent: NSData,tag: String) throws  {
        self.value = try SecKeyCreate(keyModulus: keyModulus, keyExponent: keyExponent, tag: tag)
    }
    public init(pemKey keyData: NSData, tag : String) throws {
        self.value = try SecKeyCreate(pemKey: keyData, tag: tag)
    }
}