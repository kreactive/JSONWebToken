//
//  JSONWebToken
//
//  Created by Antoine Palazzolo on 18/11/15.
//

import Foundation

public protocol SignatureValidator : JSONWebTokenValidatorType {
    func canVerifyWithSignatureAlgorithm(alg : SignatureAlgorithm) -> Bool
    func verify(input : NSData, signature : NSData) -> Bool
}
public enum SignatureValidatorError : ErrorType {
    case AlgorithmMismatch
    case BadInputData
    case SignatureMismatch
}
extension SignatureValidator {
    public func validateToken(token : JSONWebToken) -> ValidationResult {
        guard self.canVerifyWithSignatureAlgorithm(token.signatureAlgorithm) else {
            return .Failure(SignatureValidatorError.AlgorithmMismatch)
        }
        guard let input = (token.base64Parts.header+"."+token.base64Parts.payload).dataUsingEncoding(NSUTF8StringEncoding) else {
            return .Failure(SignatureValidatorError.BadInputData)
        }
        if self.verify(input, signature: token.decodedDataForPart(.Signature)) {
            return .Success
        } else {
            return .Failure(SignatureValidatorError.SignatureMismatch)
        }
    }
}