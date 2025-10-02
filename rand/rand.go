package rand

import (
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// MaxTokenBytes is a safety guard to prevent oversized allocations.
const MaxTokenBytes = 1 << 20 // 1 MiB.

// Bytes returns n cryptographically-secure random bytes from r (or crypto/rand.Reader if r==nil).
func Bytes(n int, r io.Reader) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("n must be > 0")
	}
	if n > MaxTokenBytes {
		return nil, fmt.Errorf("n too large: %d", n)
	}
	if r == nil {
		r = crand.Reader
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, fmt.Errorf("read random: %w", err)
	}
	return b, nil
}

// Hex returns a hex-encoded string of n random bytes.
func Hex(n int, r io.Reader) (string, error) {
	b, err := Bytes(n, r)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
