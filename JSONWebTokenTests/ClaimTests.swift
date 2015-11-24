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
        let validatorBase = IssuerValidator & SubjectValidator & JWTIdentifierValidator & AudienceValidator & ExpirationTimeValidator & NotBeforeValidator & IssuedAtValidator
        
        jwts.forEach {
            let validation = validatorBase.validateToken($0)
            XCTAssertTrue(validation.isValid, "\(validation)")
        }
        
        let validatorValues = IssuerValidator.withValidator {$0 == "kreactive"} &
            SubjectValidator.withValidator {$0 == "antoine"} &
            JWTIdentifierValidator.withValidator{$0 == "123456789"} &
            AudienceValidator.withValidator {$0.contains("test-app")}
        
        jwts.forEach {
            let validation = validatorValues.validateToken($0)
            XCTAssertTrue(validation.isValid, "\(validation)")
        }
    }
    func testValidateAllClaimsSigned() {
        let validator = IssuerValidator.withValidator {$0 == "kreactive"} &
            SubjectValidator.withValidator {$0 == "antoine"} &
            JWTIdentifierValidator.withValidator{$0 == "123456789"} &
            AudienceValidator.withValidator {$0.contains("test-app")} &
            HMACSignature(secret: "secret".dataUsingEncoding(NSUTF8StringEncoding)!, hashFunction: .SHA256)
        
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
        let jwt = ReadSampleWithName("empty")
        XCTAssertTrue(jwt.payload.audience == [])
        XCTAssertNil(jwt.payload.issuer)
        XCTAssertNil(jwt.payload.subject)
        XCTAssertNil(jwt.payload.jwtIdentifier)
        XCTAssertNil(jwt.payload.expiration)
        XCTAssertNil(jwt.payload.notBefore)
        XCTAssertNil(jwt.payload.issuedAt)
        
        let validator = IssuerValidator & SubjectValidator & JWTIdentifierValidator & AudienceValidator & ExpirationTimeValidator & NotBeforeValidator & IssuedAtValidator
        let validation = validator.validateToken(jwt)
        XCTAssertFalse(validation.isValid)
        
        let validatorOptional = IssuerValidator.optionalValidator & SubjectValidator.optionalValidator & JWTIdentifierValidator.optionalValidator & AudienceValidator.optionalValidator & ExpirationTimeValidator.optionalValidator & NotBeforeValidator.optionalValidator & IssuedAtValidator.optionalValidator
        let validationOpt = validatorOptional.validateToken(jwt)
        XCTAssertTrue(validationOpt.isValid)


    }
}

