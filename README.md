# Webhook Signature

[![Test](https://github.com/bernardosecades/webhook/workflows/Test/badge.svg)](https://github.com/bernardosecades/webhook/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/bernardosecades/webhook)](https://goreportcard.com/report/github.com/bernardosecades/webhook)

Webhooks are reverse APIs, so they need non-standard infrastructure. The starting point for building webhooks is that your app is generating data that your customers want. 
Generally, you’d expose that via an API, authenticate your users with an API key, etc. - but the difference with webhooks is that your customers want to be proactively 
notified of what’s happening in your app. Your API is built to receive and respond to requests, while webhooks actively send out data to other systems based on internal triggers. 
That requires you to persist information on where you’re supposed to be sending data to, and the status of those endpoints.

This library provides a way to sign your webhook events (Included prevention replay attacks).

## Create header value signature

```go
import (
    "github.com/bernardosecades/webhook"
)

secretKey := "a4c52442911b1550"
payload := []byte(`{"field":"lololo"}`)
timeSignature := time.Now().UTC()

hvs, err := webhook.CreateHeaderValueSignature("sha256", timeSignature, payload, secretKey)
```

It will generate a signature similar to:

```
1621386123,sha256=00fcdf824483bca8114f1e75ee611ce2bc9c55adfee435f7c1d487e2a8f7ed55
```

As well you can sign your events with sha512:

```
1621386123,sha512=dd34461aa148684fe2f309a373933bfd4240462232fb975538f8e9b0ad505bd2ae6f0469e1ddce4d9d84e437214bdbd4e98e2d950613c64c20e978df051b7db8
```

So you can send the event webhook to your client with some header like this:

```
X-Signature="1621386123,sha256=00fcdf824483bca8114f1e75ee611ce2bc9c55adfee435f7c1d487e2a8f7ed55"
```

## Validate payload with tolerance time

Prevent replay attacks in the client.

```go
import (
	"github.com/bernardosecades/webhook"
)

secretKey := "a4c52442911b1550"
payload := []byte(`{"field":"lololo"}`)
signature := "1621386123,sha256=00fcdf824483bca8114f1e75ee611ce2bc9c55adfee435f7c1d487e2a8f7ed55"

err := webhook.ValidatePayloadWithTolerance(payload, signature, secretKey, 5 * time.Minute)
```

The first part of signature `1621386123` it is the timestamp so the client can check if the signature is old to prevent a reply attack.

## Validate payload ignoring tolerance time 

Don`t Prevent replay attacks in the client.

```go
import (
	"github.com/bernardosecades/webhook"
)

payload := []byte(`{"field":"lololo"}`)
signature := "1621386123,sha256=00fcdf824483bca8114f1e75ee611ce2bc9c55adfee435f7c1d487e2a8f7ed55"
secretKey := "a4c52442911b1550"

err := webhook.ValidatePayloadIgnoringTolerance(payload, signature, secretKey)
```

## Errors

```go
ErrInvalidSignature = errors.New("invalid signature")
ErrTooOld           = errors.New("signature too old")
ErrInvalidHeader    = errors.New("invalid header")
```

## Example in your client

If the signature is created from this package and your client has a different stack you can see an example
in python to verify the signature generated with the format defined in this package: [See example in python](./examples/example.py)