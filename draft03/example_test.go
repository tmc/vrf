package draft03_test

import (
	"bytes"
	"fmt"

	"github.com/tmc/vrf/draft03"
)

func Example() {
	seed := bytes.Repeat([]byte{1}, draft03.SeedSize)
	priv := draft03.NewKeyFromSeed(seed)
	pub := priv.Public().(draft03.PublicKey)

	proof, err := priv.Prove([]byte("message"))
	if err != nil {
		fmt.Println(err)
		return
	}
	output, err := draft03.Verify(pub, []byte("message"), proof)
	fmt.Println(err == nil && len(output) == draft03.OutputSize)

	// Output:
	// true
}
