//
//  JSONWebToken
//
//  Created by Antoine Palazzolo on 20/11/15.
//

import Foundation


public struct ClaimValidatorError : ErrorType {
    let message : String
}
public struct ClaimValidator<T> : JSONWebTokenValidatorType {
    private var isOptional : Bool = false
    private var validator : (T) -> ValidationResult = {_ in return .Success}

    let key : String
    let transform : (AnyObject) throws -> T
    
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
    private static let StringClaimTransform = { (value : AnyObject) throws -> String in
        if let result = value as? String {
            return result
        } else {
            throw ClaimValidatorError(message: "\(value) is not a String type value")
        }
    }
    private static let DateClaimTransform = { (value : AnyObject) throws -> NSDate in
        if let numberValue = value as? NSNumber {
            return NSDate(timeIntervalSince1970: numberValue.doubleValue)
        } else {
            throw ClaimValidatorError(message: "\(value) is not a Number type value (date)")
        }
    }
    public static let issuer = ClaimValidator(claim: .Issuer, transform: StringClaimTransform)
    public static let subject = ClaimValidator(claim: .Subject, transform: StringClaimTransform)
    public static let audience = ClaimValidator(claim: .Audience, transform: { value throws -> [String] in
        if let singleAudience = value as? String {
            return [singleAudience]
        } else if let multiple = value as? [String] {
            return multiple
        } else {
            throw ClaimValidatorError(message: "audience value \(value) is not an array or string value")
        }
    })
    
    public static let expiration = ClaimValidator(claim: .ExpirationTime, transform: DateClaimTransform).withValidator { date -> ValidationResult in
        if date.timeIntervalSinceNow >= 0.0 {
            return .Success
        } else {
            return .Failure(ClaimValidatorError(message: "token is expired"))
        }
    }
    public static let notBefore = ClaimValidator(claim: .NotBefore, transform: DateClaimTransform).withValidator { date -> ValidationResult in
        if date.timeIntervalSinceNow <= 0.0 {
            return .Success
        } else {
            return .Failure(ClaimValidatorError(message: "token cannot be used before \(date)"))
        }
    }
    public static let issuedAt = ClaimValidator(claim: .IssuedAt, transform: DateClaimTransform)
    public static let jwtIdentifier = ClaimValidator(claim: .JWTIdentifier, transform: StringClaimTransform)
    
}



