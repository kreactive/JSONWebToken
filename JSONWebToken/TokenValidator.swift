//
//  TokenValidator.swift
//
//  Created by Antoine Palazzolo on 23/11/15.
//

import Foundation

public enum ValidationResult {
    case Success
    case Failure(ErrorType)
    
    public var isValid : Bool {
        if case .Success = self {
            return true
        }
        return false
    }
}
public protocol JSONWebTokenValidatorType {
    func validateToken(token : JSONWebToken) -> ValidationResult
}
public struct JSONWebTokenValidator : JSONWebTokenValidatorType  {
    private let validator : (token : JSONWebToken) -> ValidationResult
    
    public func validateToken(token : JSONWebToken) -> ValidationResult {
        return self.validator(token: token)
    }
}

public struct CombinedValidatorError : ErrorType {
    public let errors : [ErrorType]
}

func &(lhs : JSONWebTokenValidatorType, rhs : JSONWebTokenValidatorType) -> JSONWebTokenValidatorType {
    let and = { (token : JSONWebToken) -> ValidationResult in
        let errors = [lhs,rhs].map{ $0.validateToken(token) }.map { validation -> ErrorType? in
            if case ValidationResult.Failure(let error) = validation {
                return Optional.Some(error)
            } else {
                return nil
            }
            }.flatMap {$0}
        return errors.count > 0 ? .Failure(CombinedValidatorError(errors: errors)) : .Success
    }
    return JSONWebTokenValidator(validator: and)
    
}

func |(lhs : JSONWebTokenValidatorType, rhs : JSONWebTokenValidatorType) -> JSONWebTokenValidatorType {
    let or = { (token : JSONWebToken) -> ValidationResult in
        var errors = [ErrorType]()
        for validator in [lhs,rhs] {
            switch validator.validateToken(token) {
            case .Success:
                return .Success
            case .Failure(let error):
                errors.append(error)
            }
        }
        return .Failure(CombinedValidatorError(errors: errors))
        
    }
    return JSONWebTokenValidator(validator: or)
}
