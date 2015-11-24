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
            } catch JSONWebToken.Error.BadTokenStructure {
                
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
        } catch JSONWebToken.Error.CannotDecodeBase64Part(.Header,_) {
            
        } catch {
            XCTFail("should be a .CannotDecodeBase64Part(.Header) error \(error)")
        }
        
        let invalidPayloadRawJWT = ReadRawSampleWithName("invalid_payload_base64")
        do {
            let _ = try JSONWebToken(string : invalidPayloadRawJWT)
            XCTFail("should fail")
        } catch JSONWebToken.Error.CannotDecodeBase64Part(.Payload,_) {
            
        } catch {
            XCTFail("should be a .CannotDecodeBase64Part(.Payload) error \(error)")
        }
        
        let invalidSignatureRawJWT = ReadRawSampleWithName("invalid_signature_base64")
        do {
            let _ = try JSONWebToken(string : invalidSignatureRawJWT)
            XCTFail("should fail")
        } catch JSONWebToken.Error.CannotDecodeBase64Part(.Signature,_) {
            
        } catch {
            XCTFail("should be a .CannotDecodeBase64Part(.Signature) error \(error)")
        }
        
    }
    func testInvalidJSON() {
        
        let invalidHeaderRawJWT = ReadRawSampleWithName("invalid_header_json")
        do {
            let _ = try JSONWebToken(string : invalidHeaderRawJWT)
            XCTFail("should fail")
        } catch JSONWebToken.Error.InvalidJSON(.Header,_) {
            
        } catch {
            XCTFail("should be a .InvalidJSON(.Header) error \(error)")
        }
        
        let invalidPayloadRawJWT = ReadRawSampleWithName("invalid_payload_json")
        do {
            let _ = try JSONWebToken(string : invalidPayloadRawJWT)
            XCTFail("should fail")
        } catch JSONWebToken.Error.InvalidJSON(.Payload,_) {
            
        } catch {
            XCTFail("should be a .InvalidJSON(.Payload) error \(error)")
        }
        
    }
    func testInvalidJSONStructure() {
        
        let invalidHeaderRawJWT = ReadRawSampleWithName("invalid_header_json_structure")
        do {
            let _ = try JSONWebToken(string : invalidHeaderRawJWT)
            XCTFail("should fail")
        } catch JSONWebToken.Error.InvalidJSONStructure(.Header) {
            
        } catch {
            XCTFail("should be a .InvalidJSON(.Header) error \(error)")
        }
        
        let invalidPayloadRawJWT = ReadRawSampleWithName("invalid_payload_json_structure")
        do {
            let _ = try JSONWebToken(string : invalidPayloadRawJWT)
            XCTFail("should fail")
        } catch JSONWebToken.Error.InvalidJSONStructure(.Payload) {
            
        } catch {
            XCTFail("should be a .InvalidJSON(.Payload) error \(error)")
        }
        
    }
}