# `rand` — Cryptographically Secure Random Helpers for Go

This package wraps Go’s `crypto/rand` to generate **secure random bytes** and **hex tokens**.  
It is suitable for **API keys, session IDs, salts, and nonces**.

---

## Library

- `Bytes(n int, r io.Reader) ([]byte, error)`  
  Returns `n` cryptographically secure random bytes.
    - If `r == nil`, it uses `crypto/rand.Reader`.
    - Guards against invalid sizes (`n <= 0` or `n > MaxTokenBytes`).

- `Hex(n int, r io.Reader) (string, error)`  
  Returns a **hex-encoded string** of `n` random bytes.

---

## When to use

- **API keys / session IDs**: `Hex(32, nil)` → 64-character random string.
- **Salts for password hashing**: `Bytes(16, nil)` → 128-bit salt.
- **Nonces / IVs**: `Bytes(12, nil)` for AES-GCM.

---

## Security notes

- Never use `math/rand` for secrets; it’s **predictable**.
- Always use at least **128 bits** (16 bytes) for API tokens / session IDs.
- Use a unique random **salt per password** when storing password hashes.
- Use `Bytes` directly when binary output is required (e.g. crypto keys).

---

## Library usage

```go
package main

import (
	"fmt"
	"github.com/Alhuin/cryptokit/rand"
)

func main() {
	// 16 random bytes → hex string
	token, err := rand.Hex(16, nil)
	if err != nil {
		panic(err)
	}
	fmt.Println("token:", token)

	// Binary random salt (16 bytes)
	salt, err := rand.Bytes(16, nil)
	if err != nil {
		panic(err)
	}
	fmt.Printf("salt: %x\n", salt)
}
```

---

## CLI usage

From the repo root:

```bash
# 16 random bytes, hex-encoded
go run ./examples/cmd/rand -n 16 -hex

# 32 random bytes, base64-encoded
go run ./examples/cmd/rand -n 32 -raw
```

**Flags**
- `-n int` — number of random bytes (default: 16).
- `-hex` — output hex string.
- `-raw` — output base64 bytes.

Exit codes: `0` ok · `2` usage/errors.

---

## Testing

```bash
go test ./rand -v
```

---

## References

- Go `crypto/rand`: https://pkg.go.dev/crypto/rand
- OWASP Cryptographic Storage Cheatsheet: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
- NIST SP 800-90A — Recommendations for Random Number Generation  
