package rand_test

import (
	"fmt"

	"github.com/Alhuin/cryptokit/rand"
)

func ExampleHex() {
	h, err := rand.Hex(16, nil)
	if err != nil {
		panic(err)
	}
	fmt.Printf("len=%d\n", len(h))
	// Output: len=32
}

func ExampleBytes() {
	b, err := rand.Bytes(16, nil)
	if err != nil {
		panic(err)
	}
	fmt.Printf("n=%d\n", len(b))
	// Output: n=16
}
