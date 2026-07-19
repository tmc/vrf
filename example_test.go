package vrf_test

import (
	"crypto/rand"
	"fmt"

	"github.com/tmc/vrf"
)

// Example shows a full prove-and-verify round trip through the package's
// re-exported RFC 9381 API: generate a key, prove a message, then parse the
// wire-format public key and proof back and verify them.
func Example() {
	pub, priv, err := vrf.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println(err)
		return
	}

	message := []byte("hello world")
	proof, err := priv.Prove(message)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Round-trip the public key and proof through their wire encodings, as a
	// verifier receiving them over the network would.
	parsedPub, err := vrf.ParsePublicKey(pub[:])
	if err != nil {
		fmt.Println(err)
		return
	}
	parsedProof, err := vrf.ParseProof(proof[:])
	if err != nil {
		fmt.Println(err)
		return
	}

	output, err := vrf.Verify(parsedPub, message, parsedProof)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(len(output))
	// Output:
	// 64
}
