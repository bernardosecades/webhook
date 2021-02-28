package webhook

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCreateHeaderValueSignature256Success(t *testing.T) {
	payload := []byte(`{"field":"lololo"}`)
	secretKey := "a4c52442911b1550"
	timeSignature := time.Date(2021, time.May, 19, 1, 2, 3, 4, time.UTC)

	hvs, err := CreateHeaderValueSignature("sha256", timeSignature, payload, secretKey)

	assert.Nil(t, err)
	assert.Equal(t, "1621386123,sha256=00fcdf824483bca8114f1e75ee611ce2bc9c55adfee435f7c1d487e2a8f7ed55", hvs)
}

func TestCreateHeaderValueSignature512Success(t *testing.T) {
	payload := []byte(`{"field":"lololo"}`)
	secretKey := "a4c52442911b1550"
	timeSignature := time.Date(2021, time.May, 19, 1, 2, 3, 4, time.UTC)

	hvs, err := CreateHeaderValueSignature("sha512", timeSignature, payload, secretKey)

	assert.Nil(t, err)
	assert.Equal(t, "1621386123,sha512=dd34461aa148684fe2f309a373933bfd4240462232fb975538f8e9b0ad505bd2ae6f0469e1ddce4d9d84e437214bdbd4e98e2d950613c64c20e978df051b7db8", hvs)
}

func TestCreateHeaderValueSignatureWithBadHashFunc(t *testing.T) {
	payload := []byte(`{"field":"lololo"}`)
	secretKey := "a4c52442911b1550"
	timeSignature := time.Date(2021, time.May, 19, 1, 2, 3, 4, time.UTC)

	_, err := CreateHeaderValueSignature("356", timeSignature, payload, secretKey)

	assert.NotNil(t, err)
	assert.Equal(t, "invalid hash function", err.Error())
}

func TestValidatePayloadIgnoringToleranceSuccess(t *testing.T) {
	sh := "1621386123,sha256=00fcdf824483bca8114f1e75ee611ce2bc9c55adfee435f7c1d487e2a8f7ed55"
	payload := []byte(`{"field":"lololo"}`)
	secretKey := "a4c52442911b1550"

	err := ValidatePayloadIgnoringTolerance(payload, sh, secretKey)

	assert.Nil(t, err)
}

func TestValidatePayloadIgnoringToleranceWithCorruptPayload(t *testing.T) {
	sh := "1621386123,sha256=00fcdf824483bca8114f1e75ee611ce2bc9c55adfee435f7c1d487e2a8f7ed55"
	payload := []byte(`{"field":"lalala"}`)
	secretKey := "a4c52442911b1550"

	err := ValidatePayloadIgnoringTolerance(payload, sh, secretKey)

	assert.NotNil(t, err)
	assert.Equal(t, "invalid signature", err.Error())
}

func TestValidatePayloadIgnoringToleranceWithCorruptTimestamp(t *testing.T) {
	sh := "1621386125,sha256=00fcdf824483bca8114f1e75ee611ce2bc9c55adfee435f7c1d487e2a8f7ed55"
	payload := []byte(`{"field":"lololo"}`)
	secretKey := "a4c52442911b1550"

	err := ValidatePayloadIgnoringTolerance(payload, sh, secretKey)

	assert.NotNil(t, err)
	assert.Equal(t, "invalid signature", err.Error())
}

func TestValidatePayloadIgnoringToleranceWithInvalidHeaderOne(t *testing.T) {
	sh := "sha256=00fcdf824483bca8114f1e75ee611ce2bc9c55adfee435f7c1d487e2a8f7ed55"
	payload := []byte(`{"field":"lololo"}`)
	secretKey := "a4c52442911b1550"

	err := ValidatePayloadIgnoringTolerance(payload, sh, secretKey)

	assert.NotNil(t, err)
	assert.Equal(t, "invalid header", err.Error())
}

func TestValidatePayloadIgnoringToleranceWithInvalidHeaderTwo(t *testing.T) {
	sh := "1621386125,00fcdf824483bca8114f1e75ee611ce2bc9c55adfee435f7c1d487e2a8f7ed55"
	payload := []byte(`{"field":"lololo"}`)
	secretKey := "a4c52442911b1550"

	err := ValidatePayloadIgnoringTolerance(payload, sh, secretKey)

	assert.NotNil(t, err)
	assert.Equal(t, "invalid header", err.Error())
}

func TestValidatePayloadIgnoringToleranceWithInvalidHeaderThree(t *testing.T) {
	sh := "bernie,sha256=00fcdf824483bca8114f1e75ee611ce2bc9c55adfee435f7c1d487e2a8f7ed55"
	payload := []byte(`{"field":"lololo"}`)
	secretKey := "a4c52442911b1550"

	err := ValidatePayloadIgnoringTolerance(payload, sh, secretKey)

	assert.NotNil(t, err)
	assert.Equal(t, "invalid header", err.Error())
}

func TestValidatePayloadWithToleranceValidSignatureButTooOld(t *testing.T) {
	payload := []byte(`{"field":"lololo"}`)
	secretKey := "a4c52442911b1550"
	timeSignature := time.Date(2021, time.February, 28, 17, 2, 3, 4, time.UTC)
	hvs, _ := CreateHeaderValueSignature("sha256", timeSignature, payload, secretKey)

	err := ValidatePayloadWithTolerance(payload, hvs, secretKey, 5*time.Minute)

	assert.NotNil(t, err)
	assert.Equal(t, "signature too old", err.Error())
}

func TestValidatePayloadWithToleranceValidSignature(t *testing.T) {
	payload := []byte(`{"field":"lololo"}`)
	secretKey := "a4c52442911b1550"
	timeSignature := time.Now().UTC()
	hvs, _ := CreateHeaderValueSignature("sha256", timeSignature, payload, secretKey)

	err := ValidatePayloadWithTolerance(payload, hvs, secretKey, 5*time.Minute)

	assert.Nil(t, err)
}
