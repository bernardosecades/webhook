#!/usr/bin/env python

import hmac
import hashlib
from datetime import datetime

secret = 'a4c52442911b1550'
headers = dict()
headers["X-Signature"] = "1621386123,sha256=00fcdf824483bca8114f1e75ee611ce2bc9c55adfee435f7c1d487e2a8f7ed55"
payload = '{"field":"lololo"}'

timestamp, signature = headers["X-Signature"].split(',')
hashFunc, valueSignature = signature.split('=')

signatureExpected = hmac.new(
    secret,
    timestamp + payload,
    getattr(hashlib, hashFunc)
).hexdigest()

if signatureExpected == valueSignature:
    print("Signature valid: " + signatureExpected)
else:
    print("Invalid signature, sent " + valueSignature +  "but we expect " + signatureExpected)

datetimeFromHeader = datetime.fromtimestamp(int(timestamp))
differenceMinutes = (datetime.now() - datetimeFromHeader).total_seconds()/60

if differenceMinutes > 5:
    print("This signature was signed more than 5 minutes ago so we should ignore this request")
else:
    print("This signature is recently")


