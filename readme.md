# Cryptokit — Learning Cryptography in Go

> This repository is a collection of notes and implementations from my journey learning cryptography.  
> **Do not use this code in production.**

---

## Project structure

- [`rand/`](./rand) — wrappers around `crypto/rand` for generating secure random bytes and tokens.
- [`hmac/`](./hmac) — helpers for computing and verifying HMAC-SHA256 tags.
- [`examples/cmd/`](./examples/cmd) — CLI tools built on top of the libraries.

---

## Quickstart

Clone and build locally:

```bash
git clone https://github.com/Alhuin/cryptokit.git
cd cryptokit
```

## Run tests

```bash
go test ./... -v
```

## Requirements
* Go 1.24+