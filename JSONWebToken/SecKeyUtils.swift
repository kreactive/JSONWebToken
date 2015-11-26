//
//  SecKeyUtils.swift
//  JSONWebToken
//
//  A substantial portions of this code is from the Heimdall library
//  https://github.com/henrinormak/Heimdall
//
//  Heimdall - The gatekeeper of Bifrost, the road connecting the
//  world (Midgard) to Asgard, home of the Norse gods.
//
//  In iOS, Heimdall is the gatekeeper to the Keychain, offering
//  a nice wrapper for interacting with private-public RSA keys
//  and encrypting/decrypting/signing data.
//
//  Created by Henri Normak on 22/04/15.
//
//  The MIT License (MIT)
//
//  Copyright (c) 2015 Henri Normak
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.
//



import Foundation
import Security



//these methods use a keychain api side effect to create public key from raw data
public extension RSAKey {
    
    enum KeyUtilError : ErrorType {
        case NotStringReadable
        case BadPEMArmor
        case NotBase64Readable
        case BadKeyFormat
    }
    
    public static func registerOrUpdateKey(keyData : NSData, tag : String) throws -> RSAKey {
        let key : SecKey? = try {
            if let existingData = try getKeyData(tag) {
                let newData = keyData.dataByStrippingX509Header()
                if !existingData.isEqualToData(newData) {
                    try updateKey(tag, data: newData)
                }
                return try getKey(tag)
            } else {
                return try addKey(tag, data: keyData.dataByStrippingX509Header())
            }
        }()
        if let result = key {
            return RSAKey(secKey : result)
        } else {
            throw KeyUtilError.BadKeyFormat
        }
    }
    public static func registerOrUpdateKey(modulus modulus: NSData, exponent : NSData, tag : String) throws -> RSAKey {
        let combinedData = NSData(modulus: modulus, exponent: exponent)
        return try RSAKey.registerOrUpdateKey(combinedData, tag : tag)
    }
    public static func registerOrUpdatePublicPEMKey(keyData : NSData, tag : String) throws -> RSAKey {
        guard let stringValue = String(data: keyData, encoding: NSUTF8StringEncoding) else {
            throw KeyUtilError.NotStringReadable
        }
        
        let base64Content : String = try {
            //remove ----BEGIN and ----END
            let scanner = NSScanner(string: stringValue)
            scanner.charactersToBeSkipped = NSCharacterSet.whitespaceAndNewlineCharacterSet()
            if scanner.scanString("-----BEGIN", intoString: nil) {
                scanner.scanUpToString("KEY-----", intoString: nil)
                guard scanner.scanString("KEY-----", intoString: nil) else {
                    throw KeyUtilError.BadPEMArmor
                }
                
                var content : NSString? = nil
                scanner.scanUpToString("-----END", intoString: &content)
                guard scanner.scanString("-----END", intoString: nil) else {
                    throw KeyUtilError.BadPEMArmor
                }
                return content?.stringByTrimmingCharactersInSet(NSCharacterSet.whitespaceAndNewlineCharacterSet())
            }
            return nil
        }() ?? stringValue
        
        guard let decodedKeyData = NSData(base64EncodedString: base64Content, options:[.IgnoreUnknownCharacters]) else {
            throw KeyUtilError.NotBase64Readable
        }
        return try RSAKey.registerOrUpdateKey(decodedKeyData, tag: tag)
    }
    static func registeredKeyWithTag(tag : String) -> RSAKey? {
        return ((try? getKey(tag)) ?? nil).map(RSAKey.init)
    }
    static func removeKeyWithTag(tag : String) {
        do {
            try deleteKey(tag)
        } catch {}
    }
}

private func getKey(tag: String) throws -> SecKey? {
    var keyRef: AnyObject?
    
    var query = matchQueryWithTag(tag)
    query[String(kSecReturnRef)] = kCFBooleanTrue as CFBoolean
    
    let status = SecItemCopyMatching(query, &keyRef)
    
    switch status {
    case errSecSuccess:
        if keyRef != nil {
            return (keyRef as! SecKey)
        } else {
            return nil
        }
    case errSecItemNotFound:
        return nil
    default:
        throw RSAKey.Error.SecurityError(status)
    }
}
internal func getKeyData(tag: String) throws -> NSData? {
    
    var query = matchQueryWithTag(tag)
    query[String(kSecReturnData)] = kCFBooleanTrue as CFBoolean
    
    var result: AnyObject? = nil
    let status = SecItemCopyMatching(query, &result)

    switch status {
    case errSecSuccess:
        return (result as! NSData)
    case errSecItemNotFound:
        return nil
    default:
        throw RSAKey.Error.SecurityError(status)
    }
}
private func updateKey(tag: String, data: NSData) throws {
    let query = matchQueryWithTag(tag)
    let status = SecItemUpdate(query, [String(kSecValueData): data])
    guard status == errSecSuccess else {
        throw RSAKey.Error.SecurityError(status)
    }
}

private func deleteKey(tag: String) throws {
    let query = matchQueryWithTag(tag)
    let status = SecItemDelete(query)
    if status != errSecSuccess {
        throw RSAKey.Error.SecurityError(status)
    }
}
private func matchQueryWithTag(tag : String) -> Dictionary<String, AnyObject> {
    return [
        String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
        String(kSecClass): kSecClassKey as CFStringRef,
        String(kSecAttrApplicationTag): tag as CFStringRef,
    ]
}

private func addKey(tag: String, data: NSData) throws -> SecKeyRef? {
    var publicAttributes = Dictionary<String, AnyObject>()
    publicAttributes[String(kSecAttrKeyType)] = kSecAttrKeyTypeRSA
    publicAttributes[String(kSecClass)] = kSecClassKey as CFStringRef
    publicAttributes[String(kSecAttrApplicationTag)] = tag as CFStringRef
    publicAttributes[String(kSecValueData)] = data as CFDataRef
    publicAttributes[String(kSecReturnPersistentRef)] = true as CFBooleanRef
    
    var persistentRef: AnyObject?
    let status = SecItemAdd(publicAttributes, &persistentRef)
    
    if status == noErr || status == errSecDuplicateItem {
        return try getKey(tag)
    }
    throw RSAKey.Error.SecurityError(status)
}

///
/// Encoding/Decoding lengths as octets
///
private extension NSInteger {
    func encodedOctets() -> [CUnsignedChar] {
        // Short form
        if self < 128 {
            return [CUnsignedChar(self)];
        }
        
        // Long form
        let i = (self / 256) + 1
        var len = self
        var result: [CUnsignedChar] = [CUnsignedChar(i + 0x80)]
        
        for (var j = 0; j < i; j++) {
            result.insert(CUnsignedChar(len & 0xFF), atIndex: 1)
            len = len >> 8
        }
        
        return result
    }
    
    init?(octetBytes: [CUnsignedChar], inout startIdx: NSInteger) {
        if octetBytes[startIdx] < 128 {
            // Short form
            self.init(octetBytes[startIdx])
            startIdx += 1
        } else {
            // Long form
            let octets = NSInteger(octetBytes[startIdx] - 128)
            
            if octets > octetBytes.count - startIdx {
                self.init(0)
                return nil
            }
            
            var result = UInt64(0)
            
            for j in 1...octets {
                result = (result << 8)
                result = result + UInt64(octetBytes[startIdx + j])
            }
            
            startIdx += 1 + octets
            self.init(result)
        }
    }
}

///
/// Manipulating data
///
private extension NSData {
    convenience init(modulus: NSData, exponent: NSData) {
        // Make sure neither the modulus nor the exponent start with a null byte
        var modulusBytes = [CUnsignedChar](UnsafeBufferPointer<CUnsignedChar>(start: UnsafePointer<CUnsignedChar>(modulus.bytes), count: modulus.length / sizeof(CUnsignedChar)))
        let exponentBytes = [CUnsignedChar](UnsafeBufferPointer<CUnsignedChar>(start: UnsafePointer<CUnsignedChar>(exponent.bytes), count: exponent.length / sizeof(CUnsignedChar)))
        
        // Make sure modulus starts with a 0x00
        if let prefix = modulusBytes.first where prefix != 0x00 {
            modulusBytes.insert(0x00, atIndex: 0)
        }
        
        // Lengths
        let modulusLengthOctets = modulusBytes.count.encodedOctets()
        let exponentLengthOctets = exponentBytes.count.encodedOctets()
        
        // Total length is the sum of components + types
        let totalLengthOctets = (modulusLengthOctets.count + modulusBytes.count + exponentLengthOctets.count + exponentBytes.count + 2).encodedOctets()
        
        // Combine the two sets of data into a single container
        var builder: [CUnsignedChar] = []
        let data = NSMutableData()
        
        // Container type and size
        builder.append(0x30)
        builder.appendContentsOf(totalLengthOctets)
        data.appendBytes(builder, length: builder.count)
        builder.removeAll(keepCapacity: false)
        
        // Modulus
        builder.append(0x02)
        builder.appendContentsOf(modulusLengthOctets)
        data.appendBytes(builder, length: builder.count)
        builder.removeAll(keepCapacity: false)
        data.appendBytes(modulusBytes, length: modulusBytes.count)
        
        // Exponent
        builder.append(0x02)
        builder.appendContentsOf(exponentLengthOctets)
        data.appendBytes(builder, length: builder.count)
        data.appendBytes(exponentBytes, length: exponentBytes.count)
        
        self.init(data: data)
    }
    
    
    func dataByStrippingX509Header() -> NSData {
        var bytes = [CUnsignedChar](count: self.length, repeatedValue: 0)
        self.getBytes(&bytes, length:self.length)
        
        var range = NSRange(location: 0, length: self.length)
        var offset = 0
        
        // ASN.1 Sequence
        if bytes[offset++] == 0x30 {
            // Skip over length
            let _ = NSInteger(octetBytes: bytes, startIdx: &offset)
            
            let OID: [CUnsignedChar] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]
            let slice: [CUnsignedChar] = Array(bytes[offset..<(offset + OID.count)])
            
            if slice == OID {
                offset += OID.count
                
                // Type
                if bytes[offset++] != 0x03 {
                    return self
                }
                
                // Skip over the contents length field
                let _ = NSInteger(octetBytes: bytes, startIdx: &offset)
                
                // Contents should be separated by a null from the header
                if bytes[offset++] != 0x00 {
                    return self
                }
                
                range.location += offset
                range.length -= offset
            } else {
                return self
            }
        }
        
        return self.subdataWithRange(range)
    }
}