#https://github.com/jpadilla/pyjwt.git
#pip install PyJWT

import jwt
import sys
import os.path

sampleDirectory = os.path.split(sys.argv[0])[0]

def writeToSampleDirectory(content,name):
    f = open(sampleDirectory+'/'+name, 'w')
    f.write(content)
    f.close()

cryptoPayload = { 'sub': '1234567890','name': 'John Doe' }
cryptoSymSecret = 'secret'

publicKeyFile = open(sampleDirectory+'/public.pem', 'r')
cryptoPublicKey = publicKeyFile.read()
publicKeyFile.close()

privateKeyFile = open(sampleDirectory+'/private.pem', 'r')
cryptoPrivateKey = privateKeyFile.read()
privateKeyFile.close()

publicKeyFile2 = open(sampleDirectory+'/public2.pem', 'r')
cryptoPublicKey2 = publicKeyFile2.read()
publicKeyFile2.close()

privateKeyFile2 = open(sampleDirectory+'/private2.pem', 'r')
cryptoPrivateKey2 = privateKeyFile2.read()
privateKeyFile2.close()

writeToSampleDirectory(jwt.encode(cryptoPayload, 'secret', algorithm='HS256'),'HS256.jwt')
writeToSampleDirectory(jwt.encode(cryptoPayload, 'secret', algorithm='HS384'),'HS384.jwt')
writeToSampleDirectory(jwt.encode(cryptoPayload, 'secret', algorithm='HS512'),'HS512.jwt')

writeToSampleDirectory(jwt.encode(cryptoPayload, cryptoPrivateKey, algorithm='RS256'),'RS256.jwt')
writeToSampleDirectory(jwt.encode(cryptoPayload, cryptoPrivateKey, algorithm='RS384'),'RS384.jwt')
writeToSampleDirectory(jwt.encode(cryptoPayload, cryptoPrivateKey, algorithm='RS512'),'RS512.jwt')

writeToSampleDirectory(jwt.encode(cryptoPayload, cryptoPrivateKey2, algorithm='RS256'),'RS256_2.jwt')
writeToSampleDirectory(jwt.encode(cryptoPayload, cryptoPrivateKey2, algorithm='RS384'),'RS384_2.jwt')
writeToSampleDirectory(jwt.encode(cryptoPayload, cryptoPrivateKey2, algorithm='RS512'),'RS512_2.jwt')