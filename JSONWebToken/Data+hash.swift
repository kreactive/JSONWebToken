//
//  Data+hash.swift
//  JSONWebToken
//
//  Created by Antoine Palazzolo on 19/05/2020.
//

import Foundation
import CommonCrypto
import CryptoKit

extension Data {
    func sha(_ hashFunction: SignatureAlgorithm.HashFunction) -> Data {
        if #available(iOSApplicationExtension 13.0, *) {
            switch hashFunction {
            case .sha256: return Data(SHA256.hash(data: self))
            case .sha384: return Data(SHA384.hash(data: self))
            case .sha512: return Data(SHA512.hash(data: self))
            }
        } else {
            return self.withUnsafeBytes { buffer -> Data in
                switch hashFunction {
                case .sha256:
                    let result = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: Int(CC_SHA256_DIGEST_LENGTH))
                    CC_SHA256(buffer.baseAddress, CC_LONG(buffer.count), result.baseAddress)
                    return Data(buffer: result)
                case .sha384:
                    let result = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: Int(CC_SHA384_DIGEST_LENGTH))
                    CC_SHA384(buffer.baseAddress, CC_LONG(buffer.count), result.baseAddress)
                    return Data(buffer: result)
                case .sha512:
                    let result = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: Int(CC_SHA512_DIGEST_LENGTH))
                    CC_SHA512(buffer.baseAddress, CC_LONG(buffer.count), result.baseAddress)
                    return Data(buffer: result)
                }
            }
        }
    }
    func hmac(_ hashFunction: SignatureAlgorithm.HashFunction, secret: Data) -> Data {
        if #available(iOSApplicationExtension 13.0, *) {
            let key = SymmetricKey(data: secret)
            switch hashFunction {
            case .sha256:
                return Data(HMAC<SHA256>.authenticationCode(for: self, using: key))
            case .sha384:
                return Data(HMAC<SHA384>.authenticationCode(for: self, using: key))
            case .sha512:
                return Data(HMAC<SHA512>.authenticationCode(for: self, using: key))
            }
        } else {
            return self.withUnsafeBytes { buffer -> Data in
                return secret.withUnsafeBytes { secretBuffer -> Data in
                    let function: CCHmacAlgorithm
                    let resultLen: Int32
                    switch hashFunction {
                    case .sha256:
                        function = CCHmacAlgorithm(kCCHmacAlgSHA256)
                        resultLen = CC_SHA256_DIGEST_LENGTH
                    case .sha384:
                        function = CCHmacAlgorithm(kCCHmacAlgSHA384)
                        resultLen = CC_SHA384_DIGEST_LENGTH
                    case .sha512:
                        function = CCHmacAlgorithm(kCCHmacAlgSHA512)
                        resultLen = CC_SHA512_DIGEST_LENGTH
                    }
                    let result = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: Int(resultLen))
                    CCHmac(function, secretBuffer.baseAddress, secretBuffer.count, buffer.baseAddress, buffer.count, result.baseAddress)
                    return Data(buffer: result)
                }
            }
        }
    }
}
