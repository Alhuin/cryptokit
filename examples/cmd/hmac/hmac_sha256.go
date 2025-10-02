package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Alhuin/cryptokit/hmac"
)

func loadKey(keyFlag *string, keyFileFlag *string) ([]byte, error) {
	if *keyFlag != "" && *keyFileFlag != "" {
		return nil, fmt.Errorf("both -k and -keyfile are set")
	}

	// Key from flag.
	if *keyFlag != "" {
		return []byte(*keyFlag), nil
	}

	// Key from file.
	if *keyFileFlag != "" {
		b, err := os.ReadFile(*keyFileFlag)
		if err != nil {
			return nil, fmt.Errorf("reading key file: %w", err)
		}
		return []byte(strings.TrimRight(string(b), "\r\n")), nil
	}

	return nil, fmt.Errorf("no key or keyfile provided")
}

func readInput(inputPathFlag *string) ([]byte, error) {
	// Input from file.
	if *inputPathFlag != "" {
		b, err := os.ReadFile(*inputPathFlag)
		if err != nil {
			return nil, fmt.Errorf("reading input file: %w", err)
		}

		return b, nil
	}

	// Input from stdin.
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("reading input from stdin: %w", err)
	}

	if len(b) == 0 {
		return nil, errors.New("no input provided (stdin empty)")
	}

	return b, nil
}

func main() {
	keyStr := flag.String("k", "", "secret key as string")
	keyFile := flag.String("keyfile", "", "path to secret key file")
	inPath := flag.String("in", "", "input file (default: stdin)")
	verifyHex := flag.String("verify", "", "expected HMAC hex tag (verify mode)")
	flag.Parse()

	key, err := loadKey(keyStr, keyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error loading key:", err)
		os.Exit(2)
	}

	payload, err := readInput(inPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error reading input:", err)
		os.Exit(2)
	}

	tag, err := hmac.ComputeHMACSHA256(key, payload)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error computing HMAC SHA256 sum:", err)
		os.Exit(2)
	}

	if *verifyHex != "" {
		// Verify mode.
		expectedTag, err := hex.DecodeString(*verifyHex)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error decoding hex tag", err)
			os.Exit(2)
		}

		ok, err := hmac.VerifyHMACSHA256(key, payload, expectedTag)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error verifying HMAC SHA256 sum:", err)
			os.Exit(2)
		}

		if ok {
			os.Exit(0)
		}

		fmt.Fprintln(os.Stderr, "mismatch")
		os.Exit(1)
	}

	// Compute mode.
	fmt.Println(hex.EncodeToString(tag))
	os.Exit(0)
}
