//
//  TestUtils.swift
//  JSONWebToken
//
//  Created by Antoine Palazzolo on 19/11/15.
//  Copyright © 2015 Antoine Palazzolo. All rights reserved.
//

import Foundation
import JSONWebToken

func ReadRawSampleWithName(_ name : String) -> String {
    let path = Bundle(for: HMACTests.self).path(forResource: name, ofType: "jwt")!
    return try! String(contentsOfFile: path, encoding: String.Encoding.utf8)
}
func ReadSampleWithName(_ name : String) -> JSONWebToken {
    return try! JSONWebToken(string : ReadRawSampleWithName(name))
}

var SamplePublicKey : RSAKey = {
    return SampleIdentity.publicKey

}()

let SamplePrivateKey : RSAKey = {
    return SampleIdentity.privateKey
}()

let SampleIdentity : (publicKey : RSAKey,privateKey : RSAKey) = {
    let path = Bundle(for: HMACTests.self).path(forResource: "identity", ofType: "p12")!
    let p12Data = try! Data(contentsOf: URL(fileURLWithPath: path))
    return try! RSAKey.keysFromPkcs12Identity(p12Data, passphrase : "1234")
}()

let SamplePayload : JSONWebToken.Payload = {
    var payload = JSONWebToken.Payload()
    payload.issuer = "1234567890"
    payload["name"] = "John Doe"
    return payload
}()
