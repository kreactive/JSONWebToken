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
    private var optional : Bool = false
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
            if case ValidationResult.Success = validationResult {
                return validator(input)
            } else {
                return validationResult
            }
        }
        return result
    }
    public var optionalValidator : ClaimValidator<T> {
        var result = self
        result.optional = true
        return result
    }
    
    
    public func validateToken(token : JSONWebToken) -> ValidationResult {
        guard let initialValue = token.payload[self.key] else {
            if self.optional {
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

private let StringClaimTransform = { (value : AnyObject) throws -> String in
    if let result = value as? String {
        return result
    } else {
       throw ClaimValidatorError(message: "\(value) is not a String type value")
    }
}
private let DateClaimTransform = { (value : AnyObject) throws -> NSDate in
    if let numberValue = value as? NSNumber {
        return NSDate(timeIntervalSince1970: numberValue.doubleValue)
    } else {
        throw ClaimValidatorError(message: "\(value) is not a Number type value (date)")
    }
}

public let IssuerValidator = ClaimValidator(claim: .Issuer, transform: StringClaimTransform)
public let SubjectValidator = ClaimValidator(claim: .Subject, transform: StringClaimTransform)
public let AudienceValidator = ClaimValidator(claim: .Audience, transform: { value throws -> [String] in
    if let singleAudience = value as? String {
        return [singleAudience]
    } else if let multiple = value as? [String] {
        return multiple
    } else {
        throw ClaimValidatorError(message: "audience value \(value) is not an array or string value")
    }
})

public let ExpirationTimeValidator = ClaimValidator(claim: .ExpirationTime, transform: DateClaimTransform).withValidator { date in
    if date.timeIntervalSinceNow <= 0.0 {
        return .Success
    } else {
        return .Failure(ClaimValidatorError(message: "token is expired"))
    }
}
public let NotBeforeValidator = ClaimValidator(claim: .NotBefore, transform: DateClaimTransform).withValidator { date in
    if date.timeIntervalSinceNow >= 0.0 {
        return .Success
    } else {
        return .Failure(ClaimValidatorError(message: "token cannot be used before \(date)"))
    }
}
public let IssuedAtValidator = ClaimValidator(claim: .IssuedAt, transform: DateClaimTransform)
public let JWTIdentifierValidator = ClaimValidator(claim: .JWTIdentifier, transform: StringClaimTransform)
