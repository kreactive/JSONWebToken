//
//  JSONWebToken.swift
//  JSONWebToken
//
//  Created by Antoine Palazzolo on 17/11/15.
//

import Foundation

public struct JSONWebToken {
    
    public enum Error : ErrorType {
        case BadTokenStructure
        case CannotDecodeBase64Part(JSONWebToken.Part,String)
        case BadJSONStructure(JSONWebToken.Part)
        case TypeIsNotAJSONWebToken
        case InvalidSignatureAlgorithm(String)
        case MissingSignatureAlgorithm

    }
    public enum Part {
        case Header
        case Payload
        case Signature
    }
    
    public struct Payload {
        public enum RegisteredClaim : String {
            case Issuer = "iss"
            case Subject = "sub"
            case Audience = "aud"
            case ExpirationTime = "exp"
            case NotBefore = "nbf"
            case IssuedAt = "iat"
            case JWTIdentifier = "jti"
        }
        
        var jsonPayload : [String : AnyObject]
        private init(jsonPayload : [String : AnyObject]) {
            self.jsonPayload = jsonPayload
        }
        public init() {
            jsonPayload = Dictionary()
        }
        subscript(key : String) -> AnyObject? {
            get {
                let result = jsonPayload[key]
                switch result {
                case .Some(let value) where value is NSNull:
                    return nil
                case .Some(_):
                    return result
                case .None:
                    return nil
                }
            }
            set {
                if newValue == nil || newValue is NSNull {
                    jsonPayload.removeValueForKey(key)
                } else {
                    jsonPayload[key] = newValue
                }
            }
        }
        private subscript(registeredClaim : RegisteredClaim) -> AnyObject? {
            get {
                return self[registeredClaim.rawValue]
            }
            set {
                return self[registeredClaim.rawValue] = newValue
            }
        }
        public var issuer : String? {
            get {
                return (try? self[.Issuer].map(IssuerValidator.transform)) ?? nil
            }
            set {
                self[.Issuer] = newValue
            }
        }
        public var subject : String? {
            get {
                return (try? self[.Subject].map(SubjectValidator.transform)) ?? nil
            }
            set {
                self[.Subject] = newValue
            }
        }
        public var audience : [String] {
            get {
                return (try? self[.Audience].map(AudienceValidator.transform) ?? []) ?? []
            }
            set {
                switch newValue.count {
                case 0:
                    self[.Audience] = nil
                case 1:
                    self[.Audience] = newValue[0]
                default:
                    self[.Audience] = newValue
                }
            }
        }
        private static func jsonClaimValueFromDate(date : NSDate?) -> NSNumber? {
            return date.map { NSNumber(longLong: Int64($0.timeIntervalSince1970)) }
        }
        public var expiration : NSDate? {
            get {
                return (try? self[.ExpirationTime].map(ExpirationTimeValidator.transform)) ?? nil
            }
            set {
                self[.ExpirationTime] = Payload.jsonClaimValueFromDate(newValue)
            }
        }
        
        public var notBefore : NSDate? {
            get {
                return (try? self[.NotBefore].map(NotBeforeValidator.transform)) ?? nil
            }
            set {
                self[.NotBefore] = Payload.jsonClaimValueFromDate(newValue)
            }
        }
        
        public var issuedAt : NSDate? {
            get {
                return (try? self[.IssuedAt].map(IssuedAtValidator.transform)) ?? nil
            }
            set {
                self[.IssuedAt] = Payload.jsonClaimValueFromDate(newValue)
            }
        }
        public var jwtIdentifier : String? {
            get {
                return (try? self[.JWTIdentifier].map(JWTIdentifierValidator.transform)) ?? nil
            }
            set {
                self[.JWTIdentifier] = newValue
            }
        }
    }
    
    
    let signatureAlgorithm : SignatureAlgorithm
    let payload : Payload
    let base64Parts : (header : String,payload : String, signature : String)
    
    public init(string input: String) throws {

        let parts = input.componentsSeparatedByString(".")
        guard parts.count == 3 else { throw Error.BadTokenStructure }
        
        self.base64Parts = (parts[0],parts[1],parts[2])
        
        guard let headerData = NSData(base64URLEncodedString: base64Parts.header, options: []) else {
            throw Error.CannotDecodeBase64Part(.Header,base64Parts.header)
        }
        guard let payloadData = NSData(base64URLEncodedString: base64Parts.payload, options: []) else {
            throw Error.CannotDecodeBase64Part(.Payload,base64Parts.payload)
        }
        guard let jsonHeader = try NSJSONSerialization.JSONObjectWithData(headerData, options: []) as? NSDictionary else {
            throw Error.BadJSONStructure(.Header)
        }
        guard (jsonHeader["typ"] as? String).map({$0.uppercaseString == "JWT"}) ?? true else {
            throw Error.TypeIsNotAJSONWebToken
        }
        guard let signatureAlgorithm = try (jsonHeader["alg"] as? String).map(SignatureAlgorithm.init) else {
            throw Error.MissingSignatureAlgorithm
        }
        self.signatureAlgorithm = signatureAlgorithm
        
        guard let jsonPayload = try NSJSONSerialization.JSONObjectWithData(payloadData, options: []) as? [String : AnyObject] else {
            throw Error.BadJSONStructure(.Payload)
        }
        self.payload = Payload(jsonPayload: jsonPayload)
    }
    public init(payload : Payload, signer : TokenSigner? = nil) throws {
        self.signatureAlgorithm = signer?.signatureAlgorithm ?? SignatureAlgorithm.None
        self.payload = payload
        
        let header = ["alg" : self.signatureAlgorithm.jwtIdentifier , "typ" : "JWT"]
        let headerBase64 = try NSJSONSerialization.dataWithJSONObject(header, options: []).base64URLEncodedStringWithOptions([])
        let payloadBase64 = try NSJSONSerialization.dataWithJSONObject(payload.jsonPayload, options: []).base64URLEncodedStringWithOptions([])
        
        let signatureInput = headerBase64 + "." + payloadBase64
        
        let signature = try signer.map {
            try $0.sign(signatureInput.dataUsingEncoding(NSUTF8StringEncoding)!)
        } ?? NSData()
        
        let signatureBase64 = signature.base64URLEncodedStringWithOptions([])
        
        self.base64Parts = (headerBase64,payloadBase64,signatureBase64)
    }
    
    
    func decodedDataForPart(part : Part) -> NSData {
        switch part {
        case .Header:
            return NSData(base64URLEncodedString: base64Parts.header, options: []) ?? NSData()
        case .Payload:
            return NSData(base64URLEncodedString: base64Parts.payload, options: []) ?? NSData()
        case .Signature:
            return NSData(base64URLEncodedString: base64Parts.signature, options: []) ?? NSData()
        }
    }
}