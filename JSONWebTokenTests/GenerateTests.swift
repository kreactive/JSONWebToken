//
//  GenerateTests.swift
//  JSONWebToken
//
//  Created by Antoine Palazzolo on 25/11/15.
//  Copyright © 2015 Antoine Palazzolo. All rights reserved.
//

import Foundation


import JSONWebToken
import XCTest

class GenerateTests : XCTestCase {
    
    func testGenerateWithNone() {
        do {
            let jwt = try JSONWebToken(payload : SamplePayload)
            XCTAssert(jwt.decodedDataForPart(.Header) != NSData())
            XCTAssert(jwt.decodedDataForPart(.Payload) != NSData())
            XCTAssert(jwt.decodedDataForPart(.Signature) == NSData())

        } catch {
            XCTFail("should not fail \(error)")
        }
    }
    func testGenerateAllClaims() {
        do {
            var payload = JSONWebToken.Payload()
            
            payload.issuer = "kreactive"
            XCTAssertNotNil(payload.issuer)
            XCTAssert(payload.issuer == "kreactive")
            payload.issuer = nil
            XCTAssertNil(payload.issuer)
            payload.issuer = "kreactive"

            payload.subject = "antoine"
            XCTAssertNotNil(payload.subject)
            XCTAssert(payload.subject == "antoine")
            payload.subject = nil
            XCTAssertNil(payload.subject)
            payload.subject = "antoine"
            
            payload.audience = ["coucou"]
            XCTAssert(payload.audience.count == 1)
            XCTAssert(payload.audience == ["coucou"])
            payload.audience = []
            XCTAssert(payload.audience == [])
            payload.audience = ["coucou","coucou2"]
            XCTAssert(payload.audience == ["coucou","coucou2"])


            let expirationDate = NSDate.distantFuture()

            payload.expiration = expirationDate
            XCTAssertNotNil(payload.expiration)
            XCTAssertEqualWithAccuracy(payload.expiration!.timeIntervalSince1970, expirationDate.timeIntervalSince1970, accuracy: 0.9999999)
            payload.expiration = nil
            XCTAssertNil(payload.expiration)
            payload.expiration = expirationDate
            
            let notBeforeDate = NSDate.distantPast()

            payload.notBefore = notBeforeDate
            XCTAssertNotNil(payload.notBefore)
            XCTAssertEqualWithAccuracy(payload.notBefore!.timeIntervalSince1970, notBeforeDate.timeIntervalSince1970, accuracy: 0.9999999)
            payload.notBefore = nil
            XCTAssertNil(payload.notBefore)
            payload.notBefore = notBeforeDate
            
            let issuedAtDate = NSDate()
            payload.issuedAt = issuedAtDate
            XCTAssertNotNil(payload.issuedAt)
            XCTAssertEqualWithAccuracy(payload.issuedAt!.timeIntervalSince1970, issuedAtDate.timeIntervalSince1970, accuracy: 0.9999999)
            payload.issuedAt = nil
            XCTAssertNil(payload.issuedAt)
            payload.issuedAt = issuedAtDate
            
            
            let jwti = NSUUID().UUIDString
            payload.jwtIdentifier = jwti
            XCTAssert(payload.jwtIdentifier == jwti)
            payload.jwtIdentifier = nil
            XCTAssertNil(payload.jwtIdentifier)
            payload.jwtIdentifier = jwti
            
            let jwt = try JSONWebToken(payload : payload)
            if let stringData = String(data : jwt.rawData , encoding : NSUTF8StringEncoding) {
                let _ = try JSONWebToken(string : stringData)
            } else {
                XCTFail()
            }
            
        } catch {
            XCTFail("should not fail \(error)")
        }
    }
}