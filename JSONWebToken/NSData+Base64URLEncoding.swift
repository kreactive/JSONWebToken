//
//  NSData+Base64URLEncoding.swift
//  JSONWebToken
//
//  Created by Antoine Palazzolo on 17/11/15.
//  Copyright © 2015 Antoine Palazzolo. All rights reserved.
//

import Foundation

extension NSData {
    convenience init?(jwt_base64URLEncodedString base64URLEncodedString: String, options : NSDataBase64DecodingOptions) {
        let input = NSMutableString(string: base64URLEncodedString)
        input.replaceOccurrencesOfString("-",withString: "+",
            options: [.LiteralSearch],
            range: NSRange(location: 0,length: input.length)
        )
        input.replaceOccurrencesOfString("_",withString: "/",
            options: [.LiteralSearch],
            range: NSRange(location: 0,length: input.length)
        )
        switch (input.length % 4)
        {
        case 0:
            break
        case 1:
            input.appendString("===");
        case 2:
            input.appendString("==");
        case 3:
            input.appendString("=");
        default:
            fatalError("unreachable")
        }
        self.init(base64EncodedString : input as String, options : options)
    }
    func jwt_base64URLEncodedStringWithOptions(options: NSDataBase64EncodingOptions) -> String {
        let result = NSMutableString(string: self.base64EncodedStringWithOptions(options))
        result.replaceOccurrencesOfString("+",withString: "-",
            options: [.LiteralSearch],
            range: NSRange(location: 0,length: result.length)
        )
        result.replaceOccurrencesOfString("/",withString: "_",
            options: [.LiteralSearch],
            range: NSRange(location: 0,length: result.length)
        )
        result.replaceOccurrencesOfString("=",withString: "",
            options: [.LiteralSearch],
            range: NSRange(location: 0,length: result.length)
        )
        return result as String
    }
}