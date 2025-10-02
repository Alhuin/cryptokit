package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

// ComputeHMACSHA256 returns the HMAC-SHA256 tag for payload using key.
func ComputeHMACSHA256(key []byte, payload []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, errors.New("empty key")
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	tag := mac.Sum(nil)

	return tag, nil
}

// VerifyHMACSHA256 reports whether signature equals the HMAC-SHA256 of payload with key.
func VerifyHMACSHA256(key []byte, payload []byte, signature []byte) (ok bool, err error) {
	b, err := ComputeHMACSHA256(key, payload)
	if err != nil {
		return false, err
	}

	return hmac.Equal(b, signature), nil
}
