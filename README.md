# JSONWebToken
Swift 2.1 library for decoding, validating, signing and verifying JWT

# Features

- Verify and sign :
	- HMAC (**HS256**, **HS384**, **HS512**)
	- RSASSA-PKCS1-v1_5 (**RS256**, **RS384**, **RS384**)
- Validate (optionally) all [registered claims](https://tools.ietf.org/html/rfc7519#section-4.1) :
	- Issuer (**iss**)
	- Subject (**sub**)
	- Audience (**aud**)
	- Expiration Time (**exp**)
	- Not Before (**nbf**)
	- Issued At (**iat**)
	- JWT ID (**jti**)
- No external dependencies : **CommonCrypto** and **Security** framework are used for signing and verifying 
- Extensible : add your own claim validator and sign operations

[![Carthage compatible](https://img.shields.io/badge/Carthage-compatible-4BC51D.svg?style=flat)](https://github.com/Carthage/Carthage)

# Usage

## Decode & Validation

```swift
import JSONWebToken

let rawJWT : String
let jwt : JSONWebToken = try JSONWebToken(string : rawJWT)

//create the validator by combining other validators with the & or | operator
let validator = RegisteredClaimValidator.expiration & 
				RegisteredClaimValidator.notBefore.optional &
				HMACSignature(secret: "secret".dataUsingEncoding(NSUTF8StringEncoding)!, hashFunction: .SHA256)
/*
- not expired
- can be used now (optional : a jwt without nbf will be valid)
- signed with HS256 and the key "secret"
*/
let validationResult = validator.validateToken(jwt)
guard case ValidationResult.Success = validationResult else { return }

//use the token and access the payload
let issuer : String? = jwt.payload.issuer
let customClaim = jwt.payload["customClaim"] as? String
```