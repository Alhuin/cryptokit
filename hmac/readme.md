
# `hmac` — HMAC-SHA256 helpers for Go

HMAC (Hash-based Message Authentication Code) provides **integrity** and **authenticity** for messages using a **shared secret key**.  
It does **not** encrypt the message (no confidentiality).
---

## Library

- `github.com/Alhuin/cryptokit/hmac`
    - `ComputeHMACSHA256(key, payload []byte) ([]byte, error)`
    - `VerifyHMACSHA256(key, payload, signature []byte) (ok bool, err error)`

---

## When to use HMAC

- **API request signing / webhooks** (prove request authenticity; detect tampering).
- **Message/file integrity** when both sides share a secret.
- **Tokens** (e.g., HS256 JWTs)—the token is signed, not encrypted.

If you need **confidentiality**, use **AEAD encryption** (AES-GCM / ChaCha20-Poly1305).

---

## Security notes

- Use a **strong random key** (≥ 256 bits). Store/rotate it securely.
- Use **constant-time comparison** for tags (`hmac.Equal`) to prevent timing attacks.
- HMAC strength depends on the **hash** (use SHA-256/512, not MD5/SHA-1).

---

## Library usage

```go
package main

import (
	"crypto/rand"
	"fmt"
	"github.com/Alhuin/cryptokit/hmac"
)

func main() {
	// 32-byte (256-bit) random key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}

	msg := []byte("payload")
	tag, err := hmac.ComputeHMACSHA256(key, msg)
	if err != nil {
		panic(err)
	}

	ok, err := hmac.VerifyHMACSHA256(key, msg, tag)
	if err != nil {
		panic(err)
	}
	fmt.Println("verified:", ok) // true
}
```

---

## CLI usage

Build and run from the repo root:

```bash
# Compute from a file
echo -n "payload" > /tmp/p.txt
echo -n "supersecret" > /tmp/key
go run ./examples/cmd/hmac -keyfile /tmp/key -in /tmp/p.txt

# Compute from stdin
echo -n "payload" | go run ./examples/cmd/hmac -k supersecret

# Verify (success -> exit 0, no output)
TAG=$(echo -n "payload" | go run ./examples/cmd/hmac -k supersecret)
echo -n "payload" | go run ./examples/cmd/hmac -k supersecret -verify "$TAG"

# Verify (mismatch -> prints 'mismatch' to stderr, exit 1)
echo -n "tampered" | go run ./examples/cmd/hmac -k supersecret -verify "$TAG"
```

**Flags**
- `-k string` — secret key as a string (dev only).
- `-keyfile path` — read secret key from a file (preferred).
- `-in path` — input file path (default: stdin).
- `-verify hexTag` — verify mode (constant-time compare).

Exit codes: `0` ok · `1` mismatch · `2` usage/errors.

---

## Testing

```bash
go test ./hmac -v
```

---

## References

- RFC 2104 — HMAC: Keyed-Hashing for Message Authentication
- Go `crypto/hmac`: https://pkg.go.dev/crypto/hmac
- Go `crypto/sha256`: https://pkg.go.dev/crypto/sha256
- OWASP: Password Storage Cheat Sheet (for upcoming KDF work)
