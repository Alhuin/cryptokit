// Package hmac exposes small helpers for computing and verifying HMAC-SHA256
// message authentication codes using a shared secret key.
//
// What HMAC gives you:
//   - Integrity: detects tampering
//   - Authenticity: proves the message was produced by someone with the key
// What it does NOT give you:
//   - Confidentiality: the message is not encrypted
//
// Usage guidance:
//   - Use a strong random key (≥ 32 bytes) generated via crypto/rand.
//   - Compare tags with crypto/hmac.Equal to avoid timing leaks.
//   - Do not reuse the same key for both HMAC and encryption (key separation).
//   - Derive per-application keys from a root secret with HKDF (future package).
//
// Typical backend use-cases:
//   - API request signing / webhooks
//   - Integrity for internal messages/files when both sides share a secret
//
// The helpers wrap Go's standard library primitives and avoid “custom crypto”.
// See examples in example_test.go.
package hmac
