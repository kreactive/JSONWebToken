//
//  TEstesteste.swift
//  JSONWebToken
//
//  Created by Antoine Palazzolo on 23/11/15.
//  Copyright © 2015 Antoine Palazzolo. All rights reserved.
//

import Foundation




let verifier = HMACSignature(secret: "616161".dataUsingEncoding(NSUTF8StringEncoding)!, hashFunction: .SHA256)

