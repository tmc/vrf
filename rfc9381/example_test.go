package rfc9381_test

import (
	"bytes"
	"fmt"

	"github.com/tmc/vrf/rfc9381"
)

func Example() {
	seed := bytes.Repeat([]byte{1}, rfc9381.SeedSize)
	priv := rfc9381.NewKeyFromSeed(seed)
	pub := priv.Public().(rfc9381.PublicKey)

	proof, err := priv.Prove([]byte("message"))
	if err != nil {
		fmt.Println(err)
		return
	}
	output, err := rfc9381.Verify(pub, []byte("message"), proof)
	fmt.Println(err == nil && len(output) == rfc9381.OutputSize)

	// Output:
	// true
}
