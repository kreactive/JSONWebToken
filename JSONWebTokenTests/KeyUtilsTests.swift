//
//  KeyUtilsTests.swift
//  JSONWebToken
//
//  Created by Antoine Palazzolo on 25/11/15.
//  Copyright © 2015 Antoine Palazzolo. All rights reserved.
//

import Foundation


@testable import JSONWebToken
import XCTest


private let keyBase64 = "MIICCgKCAgEApmlQ3ER3KIBy8kQj6rGwYSb73qVw+H1C27QtZT05jahaEMhf9kqwdhduqk/KpdRi/ghy8r1fhee5W8yrEZbEreQBG4BCCM4T6do6Xl53gU0JNOznx7smDfZsgtCpjbnf0wuiY5sqWgWoB7IDkQwq/V/ekBPZ2J97m43tBTP6J9pMYmU/pQJGN9jxNNtum8W84d9mZWm19Kar3i3KmDi7bJSAwZGXS9MKTPfl76jHVjsZ94iQEZBTNjoYUVc/E5y3/vVroq3NfE6dh4j0dfRZhfz6HJQtqy/dHNMu14chTvQFzN+HuFRUa0swEEsNjQqFmqRkB+sMDfw1mbjP3fb46pcnWdXHQyJP0q3vePLwanvwI7u32UlyaXe9bWlb6nuzBlqfwGzm7oT021yHUtRmK3Gr5/nUWwJzjvzEOn5hvnUUU37cw9WBb+itd+r9y469tBW2vZFyIodNSzgQ5/GCPbtfRjPKZ+Lfev3G0kjBRDKhcSFc3oakqcWdBC9C1KLKFYwZMRuE3wu7sQMk4PkTg5xnnUn8m9462DljfkieNAZzBwdIbPCGtu/dhQhaJcz/Dq0FgIkwoLXYzJvzgPuZq8MqHA/eJnssELvWRLoWLncyQz1giUgZvU4v+0xcMuMqQA+TsnIAEhNG8T8hsrVqD3dQvkbaWsgCCQY0EkjHeZUCAwEAAQ=="

private let SampleKeyData = Data(base64Encoded: keyBase64, options: [])!

private let keyBase64_2 = "MIICCgKCAgEAz5wSeoffVD3coUZQYZrMGuZgtloPioEX6VUrUhjYkeKsR27vph4BQhM0Vj8t/Ej2JF4BkREV2eHnWisJoL+ZfS4LxSz0Rkc4eKhJiol12XVOtE2xxrVDcmF4HMIs+k5Nl4vyIfhGqAlrKxPDJD2hZ3ROAscMfLwmdZU7IwgZpr02hbbVZ1DA3lzt6f6r9g/EMkFNl51Bxc9WIV7ymgQrFCeH/JJydiQ5wDS133m1aeNImksIA9O/bjifVc87+FPiK2dU8I1DlRWKBw0+YG0tW9ShDuG/jVdDHtWqPamGVu12sMXugcw3vVk6xrd5cdFjKd/ToVzfBpjXftyRdWwFduQQOv+05sLxaDOH+fF20PkBKgYWYmkAkzokZo6E5Ofy8Vvzf7UyYD+1AbFJ2rZkGh1LUM2OcaqH+LYMWVZBGESIkH0DOlwAk7B78yubIWV1295Y0tuxc47Fu+fMLIZQKx6D0MXpYwp5kK9ITBWYfVpXudFv5zjXWrcIM/2UdPhpxNVHS6vBg3c14tVXExARIKNux650f/P/rL6R/6O6R8Nzr2+u2VAnyCAO7BuVo006EId9sJe0OHEKjvJskXCfLMhscan/JOu0/r9C8TwVvaPI0LLETcIl/5ip9Ht4NWuOSQ1oQ8/cEZx7v2+SkLMYDD/FjDdvycXDtix/OM0Rg28CAwEAAQ=="

private let SampleKeyData2 = Data(base64Encoded: keyBase64_2, options: [])!

class KeyUtilsTests : XCTestCase {
    override func setUp() {
        super.setUp()
        self.cleanRegisteredKeys()
    }
    override func tearDown() {
        self.cleanRegisteredKeys()
        super.tearDown()
    }
    fileprivate func cleanRegisteredKeys() {
        RSAKey.removeKeyWithTag("testAddKey")
        RSAKey.removeKeyWithTag("testAddBadKey")
        RSAKey.removeKeyWithTag("PublicPEMKey")
        RSAKey.removeKeyWithTag("ModulusExponent")
    }
    
    func testAddUpdateRemoveKey() {
        self.cleanRegisteredKeys()
        XCTAssertNil(RSAKey.registeredKeyWithTag("testAddKey"))
        do {
            try RSAKey.registerOrUpdateKey(SampleKeyData, tag : "testAddKey")
        } catch {
            XCTFail("should not fail \(error)")
        }
        XCTAssertNotNil(RSAKey.registeredKeyWithTag("testAddKey"))
        let key1Data = try! getKeyData("testAddKey")
        
        do {
            try RSAKey.registerOrUpdateKey(SampleKeyData2, tag : "testAddKey")
        } catch {
            XCTFail("should not fail \(error)")
        }
        XCTAssertNotNil(RSAKey.registeredKeyWithTag("testAddKey"))
        let key2Data = try! getKeyData("testAddKey")
        XCTAssertNotEqual(key1Data, key2Data)
        
        RSAKey.removeKeyWithTag("testAddKey")
        XCTAssertNil(RSAKey.registeredKeyWithTag("testAddKey"))
    }
    
    func testAddBadKeyFormat() {
        self.cleanRegisteredKeys()
        XCTAssertNil(RSAKey.registeredKeyWithTag("testAddBadKey"))
        do {
            try RSAKey.registerOrUpdateKey("this_is_not_a_rsa_key".data(using: String.Encoding.utf8)!, tag : "testAddBadKey")
            XCTFail("should fail")
        } catch RSAKey.KeyUtilError.badKeyFormat {}
        catch {
            XCTFail("should be a  KeyUtilError.BadKeyFormat  : \(error)")
        }
        XCTAssertNil(RSAKey.registeredKeyWithTag("testAddKey"))
  
    }
    func testAddPublicPEMKey() {
        self.cleanRegisteredKeys()
        let pemPath = Bundle(for: type(of: self)).path(forResource: "public", ofType: "pem")!
        let pemData = try! Data(contentsOf: URL(fileURLWithPath: pemPath))
        
        XCTAssertNil(RSAKey.registeredKeyWithTag("PublicPEMKey"))
        do {
            try RSAKey.registerOrUpdatePublicPEMKey(pemData, tag : "PublicPEMKey")
        }
        catch {
            XCTFail("should not fail : \(error)")
        }
        XCTAssertNotNil(RSAKey.registeredKeyWithTag("PublicPEMKey"))
        RSAKey.removeKeyWithTag("PublicPEMKey")
        XCTAssertNil(RSAKey.registeredKeyWithTag("PublicPEMKey"))
        
    }
    func testModulusExponent() {
        self.cleanRegisteredKeys()
        let modulusPath = Bundle(for: type(of: self)).path(forResource: "public", ofType: "modulus")!
        let modulusData = try! Data(contentsOf: URL(fileURLWithPath: modulusPath))
        let exponentPath = Bundle(for: type(of: self)).path(forResource: "public", ofType: "exponent")!
        let exponentData = try! Data(contentsOf: URL(fileURLWithPath: exponentPath))
        XCTAssertNil(RSAKey.registeredKeyWithTag("ModulusExponent"))
        do {
            try RSAKey.registerOrUpdateKey(modulus : modulusData, exponent : exponentData, tag : "ModulusExponent")
        }
        catch {
            XCTFail("should not fail : \(error)")
        }
        XCTAssertNotNil(RSAKey.registeredKeyWithTag("ModulusExponent"))
        RSAKey.removeKeyWithTag("ModulusExponent")
        XCTAssertNil(RSAKey.registeredKeyWithTag("ModulusExponent"))
        
    }
}
