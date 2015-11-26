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



public struct RSAPKCS1Key {
    enum Error : ErrorType {
        case SecurityError(OSStatus)
        case PublicKeyNotFoundInCertificate
        case CannotCreateCertificateFromData
        case InvalidP12ImportResult
        case InvalidP12NoIdentityFound
    }
    let value : SecKeyRef
        
    public init(secKey :SecKey) {
        self.value = secKey
    }
    public init(secCertificate cert: SecCertificate) throws {
        var trust : SecTrust? = nil
        let result = SecTrustCreateWithCertificates(cert, nil, &trust)
        if result == errSecSuccess && trust != nil {
            if let publicKey = SecTrustCopyPublicKey(trust!) {
                self.init(secKey : publicKey)
            } else {
                throw Error.PublicKeyNotFoundInCertificate
            }
        } else {
            throw Error.SecurityError(result)
        }
    }
    //Creates a certificate object from a DER representation of a certificate.
    public init(certificateData data: NSData) throws {
        if let cert = SecCertificateCreateWithData(nil, data) {
            try self.init(secCertificate : cert)
        } else {
            throw Error.CannotCreateCertificateFromData
        }
    }
    
    public static func keysFromPkcs12Identity(p12Data : NSData, passphrase : String) throws -> (publicKey : RSAPKCS1Key, privateKey : RSAPKCS1Key) {
        
        var importResult : CFArray? = nil
        let status = SecPKCS12Import(p12Data, [kSecImportExportPassphrase as String: passphrase], &importResult)
        
        guard status == errSecSuccess else { throw Error.SecurityError(status) }
        
        if let array = importResult.map({unsafeBitCast($0,NSArray.self)}),
            let content = array.firstObject as? NSDictionary,
            let identity = (content[kSecImportItemIdentity as String] as! SecIdentity?)
        {
            var privateKey : SecKey? = nil
            var certificate : SecCertificate? = nil
            let status = (
                SecIdentityCopyPrivateKey(identity, &privateKey),
                SecIdentityCopyCertificate(identity, &certificate)
            )
            guard status.0 == errSecSuccess else { throw Error.SecurityError(status.0) }
            guard status.1 == errSecSuccess else { throw Error.SecurityError(status.1) }
            if privateKey != nil && certificate != nil {
                return try (RSAPKCS1Key(secCertificate: certificate!),RSAPKCS1Key(secKey: privateKey!))
            } else {
                throw Error.InvalidP12ImportResult
            }
        } else {
            throw Error.InvalidP12NoIdentityFound
        }
    }
}

public struct RSAPKCS1Verifier : SignatureValidator {
    let hashFunction : SignatureAlgorithm.HashFunction
    let key : RSAPKCS1Key
    
    public init(key : RSAPKCS1Key, hashFunction : SignatureAlgorithm.HashFunction) {
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

public struct RSAPKCS1Signer : TokenSigner {
    enum Error : ErrorType {
        case CannotAllocateSignatureBuffer
        case SecurityError(OSStatus)
    }
    
    let hashFunction : SignatureAlgorithm.HashFunction
    let key : RSAPKCS1Key
    
    public init(hashFunction : SignatureAlgorithm.HashFunction, key : RSAPKCS1Key) {
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