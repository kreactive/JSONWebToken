//
//  ClaimTests.swift
//  JSONWebToken
//
//  Created by Antoine Palazzolo on 24/11/15.
//

import Foundation

import JSONWebToken
import XCTest

class ClaimTests : XCTestCase {

    func testValidateAllClaims() {
        let jwts = ["all_claim_valid_1","all_claim_valid_2"].map(ReadSampleWithName)
        let validatorBase = RegisteredClaimValidator.issuer & RegisteredClaimValidator.subject & RegisteredClaimValidator.jwtIdentifier & RegisteredClaimValidator.audience & RegisteredClaimValidator.expiration & RegisteredClaimValidator.notBefore & RegisteredClaimValidator.issuedAt
        
        jwts.forEach {
            let validation = validatorBase.validateToken($0)
            XCTAssertTrue(validation.isValid, "\(validation)")
        }
        
        let validatorValues = RegisteredClaimValidator.issuer.withValidator {$0 == "kreactive"} &
            RegisteredClaimValidator.subject.withValidator {$0 == "antoine"} &
            RegisteredClaimValidator.jwtIdentifier.withValidator{$0 == "123456789"} &
            RegisteredClaimValidator.audience.withValidator {$0.contains("test-app")}
        
        jwts.forEach {
            let validation = validatorValues.validateToken($0)
            XCTAssertTrue(validation.isValid, "\(validation)")
        }
    }
    func testValidateAllClaimsSigned() {
        let validator = RegisteredClaimValidator.issuer.withValidator {$0 == "kreactive"} &
            RegisteredClaimValidator.subject.withValidator {$0 == "antoine"} &
            RegisteredClaimValidator.jwtIdentifier.withValidator{$0 == "123456789"} &
            RegisteredClaimValidator.audience.withValidator {$0.contains("test-app")} &
            HMACSignature(secret: "secret".data(using: String.Encoding.utf8)!, hashFunction: .sha256)
        
        let jwt = ReadSampleWithName("all_claim_valid_2_signed")
        let validation = validator.validateToken(jwt)
        XCTAssertTrue(validation.isValid, "\(validation)")
    }
    
    func testValidateClaimsGetter() {
        let jwts = ["all_claim_valid_1","all_claim_valid_2"].map(ReadSampleWithName)
        jwts.forEach {
            XCTAssertTrue($0.payload.audience.contains("test-app"))
            XCTAssertTrue($0.payload.issuer! == "kreactive")
            XCTAssertTrue($0.payload.subject! == "antoine")
            XCTAssertTrue($0.payload.jwtIdentifier! == "123456789")
            XCTAssertTrue($0.payload.expiration!.timeIntervalSinceNow >= 0)
            XCTAssertTrue($0.payload.notBefore!.timeIntervalSinceNow <= 0)
            XCTAssertTrue($0.payload.issuedAt != nil)
        }
    }
    func testValidateClaimsEmpty() {
        let tokens = ["empty","empty2"].map(ReadSampleWithName)
        tokens.forEach { jwt in
            XCTAssertTrue(jwt.payload.audience == [])
            XCTAssertNil(jwt.payload.issuer)
            XCTAssertNil(jwt.payload.subject)
            XCTAssertNil(jwt.payload.jwtIdentifier)
            XCTAssertNil(jwt.payload.expiration)
            XCTAssertNil(jwt.payload.notBefore)
            XCTAssertNil(jwt.payload.issuedAt)
            
            let validator = RegisteredClaimValidator.issuer & RegisteredClaimValidator.subject & RegisteredClaimValidator.jwtIdentifier & RegisteredClaimValidator.audience & RegisteredClaimValidator.expiration & RegisteredClaimValidator.notBefore & RegisteredClaimValidator.issuedAt
            let validation = validator.validateToken(jwt)
            XCTAssertFalse(validation.isValid)
            
            let validatorOptional = RegisteredClaimValidator.issuer.optional & RegisteredClaimValidator.subject.optional & RegisteredClaimValidator.jwtIdentifier.optional & RegisteredClaimValidator.audience.optional & RegisteredClaimValidator.expiration.optional & RegisteredClaimValidator.notBefore.optional & RegisteredClaimValidator.issuedAt.optional
            let validationOpt = validatorOptional.validateToken(jwt)
            XCTAssertTrue(validationOpt.isValid)
        }

    }
    func testOrCombine() {
        let jwt = ReadSampleWithName("RS512")
        let verifier = RSAPKCS1Verifier(key : SamplePublicKey, hashFunction: .sha512)
        let otherVerifier = HMACSignature(secret: "secret".data(using: String.Encoding.utf8)!, hashFunction: .sha512)
        XCTAssertTrue((verifier|otherVerifier).validateToken(jwt).isValid)
        XCTAssertTrue((otherVerifier|verifier).validateToken(jwt).isValid)

    }
    func testInvalidAudience() {
        let invalidFormat = ReadSampleWithName("invalid_aud_format")
        XCTAssertTrue(invalidFormat.payload.audience == [])
        let validationFormat = RegisteredClaimValidator.audience.optional.validateToken(invalidFormat)
        XCTAssertFalse(validationFormat.isValid)
        
    }
    func testInvalidExp() {
        let invalidFormat = ReadSampleWithName("invalid_exp_format")
        XCTAssertNil(invalidFormat.payload.expiration)
        let validationFormat = RegisteredClaimValidator.expiration.optional.validateToken(invalidFormat)
        XCTAssertFalse(validationFormat.isValid)
        
        let expired = ReadSampleWithName("invalid_expired")
        XCTAssertNotNil(expired.payload.expiration)
        let validationExpired = RegisteredClaimValidator.expiration.optional.validateToken(expired)
        XCTAssertFalse(validationExpired.isValid)
    }
    func testInvalidIat() {
        let invalidFormat = ReadSampleWithName("invalid_iat_format")
        XCTAssertNil(invalidFormat.payload.issuedAt)
        let validationFormat = RegisteredClaimValidator.issuedAt.optional.validateToken(invalidFormat)
        XCTAssertFalse(validationFormat.isValid)
    }
    func testInvalidIss() {
        let invalidFormat = ReadSampleWithName("invalid_iss_format")
        XCTAssertNil(invalidFormat.payload.issuer)
        let validationFormat = RegisteredClaimValidator.issuer.optional.validateToken(invalidFormat)
        XCTAssertFalse(validationFormat.isValid)
    }
    func testInvalidJWTIdentifier() {
        let invalidFormat = ReadSampleWithName("invalid_jti_format")
        XCTAssertNil(invalidFormat.payload.jwtIdentifier)
        let validationFormat = RegisteredClaimValidator.jwtIdentifier.optional.validateToken(invalidFormat)
        XCTAssertFalse(validationFormat.isValid)
    }
    func testInvalidNbf() {
        let invalidFormat = ReadSampleWithName("invalid_nbf_format")
        XCTAssertNil(invalidFormat.payload.notBefore)
        let validationFormat = RegisteredClaimValidator.notBefore.optional.validateToken(invalidFormat)
        XCTAssertFalse(validationFormat.isValid)
        
        let expired = ReadSampleWithName("invalid_nbf_immature")
        XCTAssertNotNil(expired.payload.notBefore)
        let validationExpired = RegisteredClaimValidator.notBefore.optional.validateToken(expired)
        XCTAssertFalse(validationExpired.isValid)
    }
    func testInvalidSub() {
        let invalidFormat = ReadSampleWithName("invalid_sub_format")
        XCTAssertNil(invalidFormat.payload.subject)
        let validationFormat = RegisteredClaimValidator.subject.optional.validateToken(invalidFormat)
        XCTAssertFalse(validationFormat.isValid)
        
    }
    
    func customClaimTest() {
        let _ = ClaimValidator(key: "customClaim", transform: { (jsonValue : Any) throws -> Int in
            guard let numberValue = jsonValue as? NSNumber else {
                throw ClaimValidatorError(message: "customClaim value \(jsonValue) is not the expected Number type")
            }
            return numberValue.intValue
        }).withValidator { 1..<4 ~= $0 }
    }
}

