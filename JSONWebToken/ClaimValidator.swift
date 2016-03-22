//
//  JSONWebToken
//
//  Created by Antoine Palazzolo on 20/11/15.
//

import Foundation


public struct ClaimValidatorError : ErrorType {
    public let message : String
    public init(message : String) {
        self.message = message
    }
}
public func ClaimTransformString(value : AnyObject) throws -> String {
    if let result = value as? String {
        return result
    } else {
        throw ClaimValidatorError(message: "\(value) is not a String type value")
    }
}
public func ClaimTransformDate(value : AnyObject) throws -> NSDate {
    return try NSDate(timeIntervalSince1970: ClaimTransformNumber(value).doubleValue)
}
public func ClaimTransformNumber(value : AnyObject) throws -> NSNumber {
    if let numberValue = value as? NSNumber {
        return numberValue
    } else {
        throw ClaimValidatorError(message: "\(value) is not a Number type value")
    }
}
public func ClaimTransformArray<U>(elementTransform : (AnyObject) throws -> U, value : AnyObject) throws -> [U] {
    if let array = value as? NSArray {
        return try array.map(elementTransform)
    } else {
        throw ClaimValidatorError(message: "\(value) is not an Array type value")
    }
}
public struct ClaimValidator<T> : JSONWebTokenValidatorType {
    private var isOptional : Bool = false
    private var validator : (T) -> ValidationResult = {_ in return .Success}

    public let key : String
    public let transform : (AnyObject) throws -> T
    
    public init(key : String, transform : (AnyObject) throws -> T) {
        self.key = key
        self.transform = transform
    }

    public init(claim : JSONWebToken.Payload.RegisteredClaim, transform : (AnyObject) throws -> T) {
        self.init(key : claim.rawValue,transform : transform)
    }
    
    public func withValidator(validator : (T) -> ValidationResult) -> ClaimValidator<T> {
        var result = self
        result.validator = { input in
            let validationResult = self.validator(input)
            guard case ValidationResult.Success = validationResult else {
                return validationResult
            }
            return validator(input)
        }
        return result
    }
    public func withValidator(validator : (T) -> Bool) -> ClaimValidator<T> {
        return self.withValidator {
            return validator($0) ? .Success : .Failure(ClaimValidatorError(message: "custom validation failed for key \(self.key)"))
        }
    }
    
    
    public var optional : ClaimValidator<T> {
        var result = self
        result.isOptional = true
        return result
    }
    
    
    public func validateToken(token : JSONWebToken) -> ValidationResult {
        guard let initialValue = token.payload[self.key] else {
            if self.isOptional {
                return .Success
            } else {
                return .Failure(ClaimValidatorError(message: "missing value for claim with key \(self.key)"))
            }
        }
        do {
            return try self.validator(self.transform(initialValue))
        } catch {
            return .Failure(error)
        }
    }
}
public struct RegisteredClaimValidator {
 
    public static let issuer = ClaimValidator(claim: .Issuer, transform: ClaimTransformString)
    public static let subject = ClaimValidator(claim: .Subject, transform:  ClaimTransformString)
    public static let audience = ClaimValidator(claim: .Audience, transform: { value throws -> [String] in
        if let singleAudience = try? ClaimTransformString(value) {
            return [singleAudience]
        } else if let multiple = try? ClaimTransformArray(ClaimTransformString,value : value) {
            return multiple
        } else {
            throw ClaimValidatorError(message: "audience value \(value) is not an array or string value")
        }
    })
    
    public static let expiration = ClaimValidator(claim: .ExpirationTime, transform:  ClaimTransformDate).withValidator { date -> ValidationResult in
        if date.timeIntervalSinceNow >= 0.0 {
            return .Success
        } else {
            return .Failure(ClaimValidatorError(message: "token is expired"))
        }
    }
    public static let notBefore = ClaimValidator(claim: .NotBefore, transform: ClaimTransformDate).withValidator { date -> ValidationResult in
        if date.timeIntervalSinceNow <= 0.0 {
            return .Success
        } else {
            return .Failure(ClaimValidatorError(message: "token cannot be used before \(date)"))
        }
    }
    public static let issuedAt = ClaimValidator(claim: .IssuedAt, transform: ClaimTransformDate)
    public static let jwtIdentifier = ClaimValidator(claim: .JWTIdentifier, transform: ClaimTransformString)
    
}



