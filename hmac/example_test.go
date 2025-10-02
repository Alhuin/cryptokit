package hmac_test

import (
	crand "crypto/rand"
	"fmt"

	myhmac "github.com/Alhuin/cryptokit/hmac"
)

func ExampleComputeHMACSHA256() {
	key := make([]byte, 32)
	_, _ = crand.Read(key)

	tag, err := myhmac.ComputeHMACSHA256(key, []byte("payload"))
	if err != nil {
		panic(err)
	}
	fmt.Println(len(tag) == 32) // Output: true
}

func ExampleVerifyHMACSHA256() {
	key := make([]byte, 32)
	_, _ = crand.Read(key)
	msg := []byte("payload")

	tag, _ := myhmac.ComputeHMACSHA256(key, msg)
	ok, _ := myhmac.VerifyHMACSHA256(key, msg, tag)
	fmt.Println(ok) // Output: true
}
