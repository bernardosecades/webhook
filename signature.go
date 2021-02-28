package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"
	"time"
)

const (
	sha256Prefix = "sha256"
	sha512Prefix = "sha512"
)

// All errors reported by the package
var (
	ErrInvalidSignature = errors.New("invalid signature")
	ErrTooOld           = errors.New("signature too old")
	ErrInvalidHeader    = errors.New("invalid header")
)

type signedHeader struct {
	timestamp time.Time
	signature []byte
	hashFunc  func() hash.Hash
}

// ValidatePayloadWithTolerance validate payload to prevent reply attacks
func ValidatePayloadWithTolerance(payload []byte, sigHeader string, secret string, tolerance time.Duration) error {
	return validatePayload(payload, sigHeader, secret, tolerance, true)
}

// ValidatePayloadIgnoringTolerance validate payload without considerate replay attaks
func ValidatePayloadIgnoringTolerance(payload []byte, sigHeader string, secret string) error {
	return validatePayload(payload, sigHeader, secret, 0*time.Second, false)
}

// CreateHeaderValueSignature create value signature with format: "timestamp,hashFunc=signature"
func CreateHeaderValueSignature(hf string, t time.Time, payload []byte, secret string) (string, error) {
	hashFunction, err := hashFunc(hf)
	if err != nil {
		return "", err
	}

	sig := createSignature(hashFunction, t, payload, secret)

	return fmt.Sprintf("%s,%s=%s", strconv.FormatInt(t.Unix(), 10), hf, hex.EncodeToString(sig)), nil
}

func hashFunc(hashFunc string) (func() hash.Hash, error) {
	switch hashFunc {
	case sha256Prefix:
		return sha256.New, nil
	case sha512Prefix:
		return sha512.New, nil
	default:
		return nil, errors.New("invalid hash function")
	}
}

func parseSignatureHeader(header string) (*signedHeader, error) {
	sh := &signedHeader{}

	sigParts := strings.SplitN(header, ",", 2)
	if len(sigParts) != 2 {
		return nil, ErrInvalidHeader
	}

	timestamp, err := strconv.ParseInt(sigParts[0], 10, 64)
	if err != nil {
		return nil, ErrInvalidHeader
	}

	sh.timestamp = time.Unix(timestamp, 0)

	algoSigParts := strings.SplitN(sigParts[1], "=", 2)
	if len(algoSigParts) != 2 {
		return nil, ErrInvalidHeader
	}

	sh.hashFunc, err = hashFunc(algoSigParts[0])
	if err != nil {
		return nil, ErrInvalidHeader
	}

	sig, err := hex.DecodeString(algoSigParts[1])
	if err != nil {
		return nil, ErrInvalidHeader
	}

	sh.signature = sig

	return sh, nil
}

func createSignature(hashFunc func() hash.Hash, t time.Time, payload []byte, secret string) []byte {
	mac := hmac.New(hashFunc, []byte(secret))
	mac.Write([]byte(fmt.Sprintf("%d", t.Unix())))
	mac.Write(payload)

	return mac.Sum(nil)
}

func validatePayload(payload []byte, sigHeader string, secret string, tolerance time.Duration, enforceTolerance bool) error {
	header, err := parseSignatureHeader(sigHeader)
	if err != nil {
		return err
	}

	expectedSignature := createSignature(header.hashFunc, header.timestamp, payload, secret)
	expiredTimeStamp := time.Since(header.timestamp) > tolerance

	if enforceTolerance && expiredTimeStamp {
		return ErrTooOld
	}

	if hmac.Equal(expectedSignature, header.signature) {
		return nil
	}

	return ErrInvalidSignature
}
