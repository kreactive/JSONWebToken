//
//  ECDSATests.swift
//  JSONWebToken
//
//  Created by Antoine Palazzolo on 25/11/15.
//

import Foundation

import JSONWebToken
import XCTest

class ECDSATests : XCTestCase {
    
    func testES256Decode() {
        let _ = ReadSampleWithName("ES256")
    }
    func testES384Decode() {
        let _ = ReadSampleWithName("ES384")
    }
    func testES512Decode() {
        let _ = ReadSampleWithName("ES512")
    }
}