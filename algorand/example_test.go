package algorand_test

import (
	"bytes"
	"fmt"

	"github.com/tmc/vrf/algorand"
)

func Example() {
	seed := bytes.Repeat([]byte{1}, algorand.SeedSize)
	priv := algorand.NewKeyFromSeed(seed)
	pub := priv.Public().(algorand.PublicKey)

	proof, err := priv.Prove([]byte("message"))
	if err != nil {
		fmt.Println(err)
		return
	}
	output, err := algorand.Verify(pub, []byte("message"), proof)
	fmt.Println(err == nil && len(output) == algorand.OutputSize)

	// Output:
	// true
}
