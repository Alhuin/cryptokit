// Package rand provides thin, safe wrappers around crypto/rand for generating
// cryptographically secure random bytes and tokens.
//
// Typical backend use-cases:
//   - API keys / session IDs: Hex(32, nil) → 32 random bytes (64 hex chars)
//   - Salts for password hashing: Bytes(16, nil)
//   - Nonces / IVs: Bytes(12, nil) for AES-GCM
//
// Security notes:
//   - Do not use math/rand for secrets; it is predictable.
//   - Prefer at least 16 bytes (128 bits) for tokens.
//   - If r is nil, functions use crypto/rand.Reader.
//
// The package intentionally keeps a small API surface for ease of review.
// See examples in example_test.go.
package rand
