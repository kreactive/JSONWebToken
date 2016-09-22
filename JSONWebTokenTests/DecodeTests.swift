//
//  DecodeTests.swift
//  JSONWebToken
//
//  Created by Antoine Palazzolo on 24/11/15.
//

import Foundation

import JSONWebToken
import XCTest

class DecodeTests : XCTestCase {
    func testInvalidStructure() {
        let rawJWT = ["invalid_structure","invalid_structure_2"].map(ReadRawSampleWithName)
        rawJWT.forEach {
            do {
                let _ = try JSONWebToken(string : $0)
                XCTFail("should fail")
            } catch JSONWebToken.Error.badTokenStructure {
                
            } catch {
                XCTFail("should be a BadTokenStructure error \(error)")
            }
        }
    }
    func testInvalidBase64() {
        
        let invalidHeaderRawJWT = ReadRawSampleWithName("invalid_header_base64")
        do {
            let _ = try JSONWebToken(string : invalidHeaderRawJWT)
            XCTFail("should fail")
        } catch JSONWebToken.Error.cannotDecodeBase64Part(.header,_) {
            
        } catch {
            XCTFail("should be a .CannotDecodeBase64Part(.Header) error \(error)")
        }
        
        let invalidPayloadRawJWT = ReadRawSampleWithName("invalid_payload_base64")
        do {
            let _ = try JSONWebToken(string : invalidPayloadRawJWT)
            XCTFail("should fail")
        } catch JSONWebToken.Error.cannotDecodeBase64Part(.payload,_) {
            
        } catch {
            XCTFail("should be a .CannotDecodeBase64Part(.Payload) error \(error)")
        }
        
        let invalidSignatureRawJWT = ReadRawSampleWithName("invalid_signature_base64")
        do {
            let _ = try JSONWebToken(string : invalidSignatureRawJWT)
            XCTFail("should fail")
        } catch JSONWebToken.Error.cannotDecodeBase64Part(.signature,_) {
            
        } catch {
            XCTFail("should be a .CannotDecodeBase64Part(.Signature) error \(error)")
        }
        
    }
    func testInvalidJSON() {
        
        let invalidHeaderRawJWT = ReadRawSampleWithName("invalid_header_json")
        do {
            let _ = try JSONWebToken(string : invalidHeaderRawJWT)
            XCTFail("should fail")
        } catch JSONWebToken.Error.invalidJSON(.header,_) {
            
        } catch {
            XCTFail("should be a .InvalidJSON(.Header) error \(error)")
        }
        
        let invalidPayloadRawJWT = ReadRawSampleWithName("invalid_payload_json")
        do {
            let _ = try JSONWebToken(string : invalidPayloadRawJWT)
            XCTFail("should fail")
        } catch JSONWebToken.Error.invalidJSON(.payload,_) {
            
        } catch {
            XCTFail("should be a .InvalidJSON(.Payload) error \(error)")
        }
        
    }
    func testInvalidJSONStructure() {
        
        let invalidHeaderRawJWT = ReadRawSampleWithName("invalid_header_json_structure")
        do {
            let _ = try JSONWebToken(string : invalidHeaderRawJWT)
            XCTFail("should fail")
        } catch JSONWebToken.Error.invalidJSONStructure(.header) {
            
        } catch {
            XCTFail("should be a .InvalidJSON(.Header) error \(error)")
        }
        
        let invalidPayloadRawJWT = ReadRawSampleWithName("invalid_payload_json_structure")
        do {
            let _ = try JSONWebToken(string : invalidPayloadRawJWT)
            XCTFail("should fail")
        } catch JSONWebToken.Error.invalidJSONStructure(.payload) {
            
        } catch {
            XCTFail("should be a .InvalidJSON(.Payload) error \(error)")
        }
    }
    func testHeaderContent() {
        let missingAlgRawJWT = ReadRawSampleWithName("invalid_missing_alg")
        do {
            let _ = try JSONWebToken(string : missingAlgRawJWT)
            XCTFail("should fail")
        } catch JSONWebToken.Error.missingSignatureAlgorithm {
            
        } catch {
            XCTFail("should be a .MissingSignatureAlgorithm error \(error)")
        }
        
        let invalidAlgRawJWT = ReadRawSampleWithName("invalid_alg")
        do {
            let _ = try JSONWebToken(string : invalidAlgRawJWT)
            XCTFail("should fail")
        } catch JSONWebToken.Error.invalidSignatureAlgorithm("RS9000") {
            
        } catch {
            XCTFail("should be a .InvalidSignatureAlgorithm error \(error)")
        }
        
        let missingTyp = ReadRawSampleWithName("valid_missing_typ")
        do {
            let _ = try JSONWebToken(string : missingTyp)
        } catch {
            XCTFail("should not fail \(error)")
        }
        
        let invalidTyp = ReadRawSampleWithName("invalid_typ")
        do {
            let _ = try JSONWebToken(string : invalidTyp)
            XCTFail("should fail")
        } catch JSONWebToken.Error.typeIsNotAJSONWebToken {
            
        } catch {
            XCTFail("should be a .TypeIsNotAJSONWebToken error \(error)")
        }
    }
}
