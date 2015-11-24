//
//  TestUtils.swift
//  JSONWebToken
//
//  Created by Antoine Palazzolo on 19/11/15.
//  Copyright © 2015 Antoine Palazzolo. All rights reserved.
//

import Foundation
import JSONWebToken

func ReadRawSampleWithName(name : String) -> String {
    let path = NSBundle(forClass: HMACTests.self).pathForResource(name, ofType: "jwt")!
    return try! String(contentsOfFile: path, encoding: NSUTF8StringEncoding)
}
func ReadSampleWithName(name : String) -> JSONWebToken {
    return try! JSONWebToken(string : ReadRawSampleWithName(name))
}

var SamplePublicKey : SignatureKey = {
    let path = NSBundle(forClass: HMACTests.self).pathForResource("public", ofType: "pem")!
    let data = NSData(contentsOfFile : path)!
    return try! SignatureKey(pemKey: data, tag : "testPublicKey")
}()

var SamplePrivateKey : SignatureKey = {
    let path = NSBundle(forClass: HMACTests.self).pathForResource("private", ofType: "pem")!
    let data = NSData(contentsOfFile : path)!
    return try! SignatureKey(pemKey: data, tag : "testPrivateKey")
}()