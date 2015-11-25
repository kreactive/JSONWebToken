//
//  RSASSA_PSSTests.swift
//  JSONWebToken
//
//  Created by Antoine Palazzolo on 25/11/15.
//

import Foundation
import JSONWebToken
import XCTest

class RSASSA_PSSTests : XCTestCase {
    
    func testPS256Decode() {
        let _ = ReadSampleWithName("PS256")
    }
    func testPS384Decode() {
        let _ = ReadSampleWithName("PS384")
    }
    func testPS512Decode() {
        let _ = ReadSampleWithName("PS512")
    }
}