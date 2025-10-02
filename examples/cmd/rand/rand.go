package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	"github.com/Alhuin/cryptokit/rand"
)

func main() {
	n := flag.Int("n", 16, "number of random bytes")
	b64 := flag.Bool("b64", false, "output as base64")
	hex := flag.Bool("hex", false, "output hex tag")
	flag.Parse()

	if *n < 0 {
		fmt.Fprintf(os.Stderr, "negative number of bytes: %d\n", *n)
		os.Exit(2)
	}

	if *b64 && *hex {
		fmt.Fprintln(os.Stderr, "cannot provide both -b64 and -hex output")
		os.Exit(2)
	}

	if !*b64 && !*hex {
		*hex = true
	}

	if *hex {
		// nil reader uses rand.Reader.
		h, err := rand.Hex(*n, nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		fmt.Println(h)
		os.Exit(0)
	}

	if *b64 {
		// nil reader uses rand.Reader.
		b, err := rand.Bytes(*n, nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		fmt.Printf("%s\n", base64.StdEncoding.EncodeToString(b))
		os.Exit(0)
	}
}
