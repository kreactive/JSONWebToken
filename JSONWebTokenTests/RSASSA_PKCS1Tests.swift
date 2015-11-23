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
        let jwtSource = "eyJhbGciOiJSUzI1NiJ9.eyJqdGkiOiIwZGY1NTM3MC02ODVjLTRmYmQtODVmMy1hOGZlYzdiYWFhY2IiLCJleHAiOjE0NDc5Mzk3MDMsIm5iZiI6MCwiaWF0IjoxNDQ3OTM5NjQzLCJpc3MiOiJodHRwOi8vMTkyLjE2OC45OS4xMDA6ODk4OS9hdXRoL3JlYWxtcy9tYXN0ZXIiLCJhdWQiOiJ0ZXN0Y2xpZW50aWQiLCJzdWIiOiI1YjQ0NDg5Ny1mZjA1LTQ0NTMtOGNjOC0yNDk4ZTZlYzQ0NmEiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0ZXN0Y2xpZW50aWQiLCJzZXNzaW9uX3N0YXRlIjoiNWE0MWY3OGYtY2QxNi00YTkyLTgwZGUtZGY2ZWNhZWRjMTIzIiwiY2xpZW50X3Nlc3Npb24iOiI0YzI0ZTlhNy1jMzE0LTRlODItYmM1OS1kOWQ4OThiYmRhY2EiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovLzE5Mi4xNjguOTkuMTAwOjg5ODkiXSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJ2aWV3LXByb2ZpbGUiXX19LCJuYW1lIjoiYW50b2luZSBwYWxhenpvbG8iLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhbnRvaW5lIiwiZ2l2ZW5fbmFtZSI6ImFudG9pbmUiLCJmYW1pbHlfbmFtZSI6InBhbGF6em9sbyIsImVtYWlsIjoiYS5wYWxhenpvbG9AZ21haWwuY29tIn0.Cxk2eqmJp557Akt5qU6BjbbTPropU80dQjr1zGL0A_JcSRwDW_-xdFiFCQsPKqWWEccqFIv0t3S9x7VMuMvqHultVvSy8QnTNGf0Z9SFGUsI_5GhvBjS09RDgWhEKRZqliOTyllopY-vFCHF6CjNXfJCjwNVqaki-Xa7TbA7zxwmmBc5U5NaajLfovYWfQAPpBUfh1g6bXdZo9bqmpCXaGYqPjXaUaisjWdm2PEVRrewcu93d_SrsLXlHo0mTFjVFEmvDTHUbI3olfTxxOHj2n1MQY3r_NudOjGUJR1Qk2uka5xlOu2v2oehmIeMeVvZnprKYM2e20djdism7P6mxw"
        
        let publicKeySource = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqljcN7ksatetBXG1YmvPcoL0L7+Epiq8T01av+aa2xKsd6BVKsoUmqJ4Vva/z8NTTg03gxBrT1K6XbiavUzui+1FT76NPJE1JQKei6leCSjV4BmcwZ1JBPxkUtEI9884bEefWUk1YRcIE2N42elMJd1qq4QXV5i5BHbL6P+U+Ez9uzSHrYTaFMDZR9r8Ou9GW+nTuT6hhjeB0bOqtCEsYlU6Lb8R1bqVmoT5YwW/NYxOVY2bcb73HylY/b3cnCw+CSzsYH0AnRICiUWX5AHd+b/kMhp3ewImuunqM6FGidvYMDggn6q1wocTPmuseffsaKyT6nUzYN4s7vIo8AzT6QIDAQAB"
        
        let jwt = try! JSONWebToken(string : jwtSource)
        let key = try! SignatureKey(keyData : NSData(base64EncodedString: publicKeySource, options: [])!, tag : "coucou")
        
        let verifier = RSASSA_PKCS1Verifier(hashFunction: .SHA256, key : key)
        XCTAssertTrue(verifier.validateToken(jwt).isValid)
    }
    func testRS256VerifyFailure() {
        let jwtSource = "eyJhbGciOiJSUzI1NiJ9.eyJqdGkiOiIwZGY1NTM3MC02ODVjLTRmYmQtODVmMy1hOGZlYzdiYWFhY2IiLCJleHAiOjE0NDc5Mzk3MDMsIm5iZiI6MCwiaWF0IjoxNDQ3OTM5NjQzLCJpc3MiOiJodHRwOi8vMTkyLjE2OC45OS4xMDA6ODk4OS9hdXRoL3JlYWxtcy9tYXN0ZXIiLCJhdWQiOiJ0ZXN0Y2xpZW50aWQiLCJzdWIiOiI1YjQ0NDg5Ny1mZjA1LTQ0NTMtOGNjOC0yNDk4ZTZlYzQ0NmEiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0ZXN0Y2xpZW50aWQiLCJzZXNzaW9uX3N0YXRlIjoiNWE0MWY3OGYtY2QxNi00YTkyLTgwZGUtZGY2ZWNhZWRjMTIzIiwiY2xpZW50X3Nlc3Npb24iOiI0YzI0ZTlhNy1jMzE0LTRlODItYmM1OS1kOWQ4OThiYmRhY2EiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovLzE5Mi4xNjguOTkuMTAwOjg5ODkiXSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJ2aWV3LXByb2ZpbGUiXX19LCJuYW1lIjoiYW50b2luZSBwYWxhenpvbG8iLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhbnRvaW5lIiwiZ2l2ZW5fbmFtZSI6ImFudG9pbmUiLCJmYW1pbHlfbmFtZSI6InBhbGF6em9sbyIsImVtYWlsIjoiYS5wYWxhenpvbG9AZ21haWwuY29tIn0.Cxk2eqmJp557Akt5qU6BjbbTPropU80dQjr1zGL0A_JcSRwDW_-xdFiFCQsPKqWWEccqFIv0t3S9x7VMuMvqHultVvSy8QnTNGf0Z9SFGUsI_5GhvBjS09RDgWhEKRZqliOTyllopY-vFCHF6CjNXfJCjwNVqaki-Xa7TbA7zxwmmBc5U5NaajLfovYWfQAPpBUfh1g6bXdZo9bqmpCXaGYqPjXaUaisjWdm2PEVRrewcu93d_SrsLXlHo0mTFjVFEmvDTHUbI3olfTxxOHj2n1MQY3r_NudOjGUJR1Qk2uka5xlOu2v2oehmIeMeVvZnprKYM2e20djdism7P6mxw"
        
        let publicKeySource = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqljcN7ksatetBXG1YmvPcoL0L7+Epiq8T01av+aa2xKsd6BVKsoUmqJ4Vva/z8NTTg03gxBrT1K6XbiavVzui+1FT76NPJE1JQKei6leCSjV4BmcwZ1JBPxkUtEI9884bEefWUk1YRcIE2N42elMJd1qq4QXV5i5BHbL6P+U+Ez9uzSHrYTaFMDZR9r8Ou9GW+nTuT6hhjeB0bOqtCEsYlU6Lb8R1bqVmoT5YwW/NYxOVY2bcb73HylY/b3cnCw+CSzsYH0AnRICiUWX5AHd+b/kMhp3ewImuunqM6FGidvYMDggn6q1wocTPmuseffsaKyT6nUzYN4s7vIo8AzT6QIDAQAB"
        
        let jwt = try! JSONWebToken(string : jwtSource)
        let key = try! SignatureKey(keyData : NSData(base64EncodedString: publicKeySource, options: [])!, tag : "coucou")
        let verifier = RSASSA_PKCS1Verifier(hashFunction: .SHA256, key : key)
        XCTAssertFalse(verifier.validateToken(jwt).isValid)
    }
    
}
