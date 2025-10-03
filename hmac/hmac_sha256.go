package hmac

import (
	chmac "crypto/hmac"
	"crypto/sha256"
	"errors"
)

// ComputeHMACSHA256 returns the HMAC-SHA256 tag for payload using key.
func ComputeHMACSHA256(key, payload []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, errors.New("empty key")
	}

	mac := chmac.New(sha256.New, key)
	mac.Write(payload)
	tag := mac.Sum(nil)

	return tag, nil
}

// VerifyHMACSHA256 reports whether signature equals the HMAC-SHA256 of payload with key.
func VerifyHMACSHA256(key, payload, signature []byte) (ok bool, err error) {
	b, err := ComputeHMACSHA256(key, payload)
	if err != nil {
		return false, err
	}

	return chmac.Equal(b, signature), nil
}
