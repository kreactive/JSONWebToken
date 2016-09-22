//
//  HMACTests.swift
//  JSONWebToken
//
//  Created by Antoine Palazzolo on 23/11/15.
//

import XCTest
import JSONWebToken
import Security

class HMACTests : XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    func testHS256VerifySuccess() {
        let jwt = ReadSampleWithName("HS256")
        let verifier = HMACSignature(secret: "secret".data(using: String.Encoding.utf8)!, hashFunction: .sha256)
        let result = verifier.validateToken(jwt)
        XCTAssertTrue(result.isValid)
    }
    func testHS256VerifyFailure() {
        let jwt = ReadSampleWithName("HS256")
        let verifier = HMACSignature(secret: "secretr".data(using: String.Encoding.utf8)!, hashFunction: .sha256)
        let result = verifier.validateToken(jwt)
        XCTAssertFalse(result.isValid)
    }
    func testHS384VerifySuccess() {
        let jwt = ReadSampleWithName("HS384")
        let verifier = HMACSignature(secret: "secret".data(using: String.Encoding.utf8)!, hashFunction: .sha384)
        let result = verifier.validateToken(jwt)
        XCTAssertTrue(result.isValid)
    }
    func testHS384VerifyFailure() {
        let jwt = ReadSampleWithName("HS384")
        let verifier = HMACSignature(secret: "secretr".data(using: String.Encoding.utf8)!, hashFunction: .sha384)
        let result = verifier.validateToken(jwt)
        XCTAssertFalse(result.isValid)
    }
    func testHS512VerifySuccess() {
        let jwt = ReadSampleWithName("HS512")
        let verifier = HMACSignature(secret: "secret".data(using: String.Encoding.utf8)!, hashFunction: .sha512)
        let result = verifier.validateToken(jwt)
        XCTAssertTrue(result.isValid)
    }
    func testHS512VerifyFailure() {
        let jwt = ReadSampleWithName("HS512")
        let verifier = HMACSignature(secret: "secretr".data(using: String.Encoding.utf8)!, hashFunction: .sha512)
        let result = verifier.validateToken(jwt)
        XCTAssertFalse(result.isValid)
    }
    
    func testHS256Sign() {
        let signer = HMACSignature(secret: "secret".data(using: String.Encoding.utf8)!, hashFunction: .sha256)
        do {
            let jwt = try JSONWebToken(payload : SamplePayload, signer : signer)
            let verifier = signer
            let result = verifier.validateToken(jwt)
            XCTAssertTrue(result.isValid)
        } catch {
            XCTFail("sign failed \(error)")
        }

    }
    func testHS384Sign() {
        let signer = HMACSignature(secret: "secret".data(using: String.Encoding.utf8)!, hashFunction: .sha384)
        do {
            let jwt = try JSONWebToken(payload : SamplePayload, signer : signer)
            let verifier = signer
            let result = verifier.validateToken(jwt)
            XCTAssertTrue(result.isValid)
        } catch {
            XCTFail("sign failed \(error)")
        }
    }
    func testHS512Sign() {
        let signer = HMACSignature(secret: "secret".data(using: String.Encoding.utf8)!, hashFunction: .sha512)
        do {
            let jwt = try JSONWebToken(payload : SamplePayload, signer : signer)
            let verifier = signer
            let result = verifier.validateToken(jwt)
            XCTAssertTrue(result.isValid)
        } catch {
            XCTFail("sign failed \(error)")
        }
    }
}
