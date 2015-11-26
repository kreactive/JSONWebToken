//
//  JSONWebTokenTests.swift
//  JSONWebTokenTests
//
//  Created by Antoine Palazzolo on 17/11/15.
//  Copyright © 2015 Antoine Palazzolo. All rights reserved.
//

import XCTest
import JSONWebToken
import Security

class RSASSA_PKCS1Tests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testRS256VerifySuccess() {
        let jwt = ReadSampleWithName("RS256")
        let verifier = RSAPKCS1Verifier(key : SamplePublicKey, hashFunction: .SHA256)
        XCTAssertTrue(verifier.validateToken(jwt).isValid)
    }
    func testRS384VerifySuccess() {
        let jwt = ReadSampleWithName("RS384")
        let verifier = RSAPKCS1Verifier( key : SamplePublicKey,hashFunction: .SHA384)
        XCTAssertTrue(verifier.validateToken(jwt).isValid)
    }
    func testRS512VerifySuccess() {
        let jwt = ReadSampleWithName("RS512")
        let verifier = RSAPKCS1Verifier( key : SamplePublicKey,hashFunction: .SHA512)
        XCTAssertTrue(verifier.validateToken(jwt).isValid)
    }
    
    func testRS256VerifyFailure() {
        let jwt = ReadSampleWithName("RS256_2")
        let verifier = RSAPKCS1Verifier(key : SamplePublicKey , hashFunction: .SHA256)
        XCTAssertFalse(verifier.validateToken(jwt).isValid)
    }
    func testRS384VerifyFailure() {
        let jwt = ReadSampleWithName("RS384_2")
        let verifier = RSAPKCS1Verifier(key : SamplePublicKey, hashFunction: .SHA384)
        XCTAssertFalse(verifier.validateToken(jwt).isValid)
    }
    func testRS512VerifyFailure() {
        let jwt = ReadSampleWithName("RS512_2")
        let verifier = RSAPKCS1Verifier(key : SamplePublicKey, hashFunction: .SHA512)
        XCTAssertFalse(verifier.validateToken(jwt).isValid)
    }
    func testVerifyOtherAlg() {
        let jwt = ReadSampleWithName("HS256")
        let verifier = RSAPKCS1Verifier(key : SamplePublicKey, hashFunction: .SHA512)
        XCTAssertFalse(verifier.validateToken(jwt).isValid)
    }
    func testRS256Sign() {
        let signer = RSAPKCS1Signer(hashFunction: .SHA256, key: SamplePrivateKey)
        do {
            let jwt = try JSONWebToken(payload : SamplePayload, signer : signer)
            let verifier = RSAPKCS1Verifier(key : SamplePublicKey, hashFunction: .SHA256)
            XCTAssertTrue(verifier.validateToken(jwt).isValid)
        } catch {
            XCTFail("should not fail \(error)")
        }
    }
    func testRS384Sign() {
        let signer = RSAPKCS1Signer(hashFunction: .SHA384, key: SamplePrivateKey)
        do {
            let jwt = try JSONWebToken(payload : SamplePayload, signer : signer)
            let verifier = RSAPKCS1Verifier(key : SamplePublicKey, hashFunction: .SHA384)
            XCTAssertTrue(verifier.validateToken(jwt).isValid)
        } catch {
            XCTFail("should not fail \(error)")
        }
    }
    func testRS512Sign() {
        let signer = RSAPKCS1Signer(hashFunction: .SHA512, key: SamplePrivateKey)
        do {
            let jwt = try JSONWebToken(payload : SamplePayload, signer : signer)
            let verifier = RSAPKCS1Verifier(key : SamplePublicKey, hashFunction: .SHA512)
            XCTAssertTrue(verifier.validateToken(jwt).isValid)
        } catch {
            XCTFail("should not fail \(error)")
        }
    }
    func testCertificateImport() {
        let certificateData = NSData(contentsOfFile: NSBundle(forClass : self.dynamicType).pathForResource("TestCertificate", ofType: "cer")!)!
        do {
            let _ = try RSAKey(certificateData : certificateData)
        } catch {
            XCTFail("should not fail \(error)")
        }
    }
    
}
