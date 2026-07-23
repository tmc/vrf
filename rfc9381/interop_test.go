package rfc9381

import (
	"bytes"
	"testing"
)

// These vectors were generated from non-RFC inputs by vrf-rfc9381 v0.0.7,
// a Rust implementation, at commit 67a36e8af3704d8a6ba926c98d30b8eff1f4c21f:
// https://github.com/OtaK/vrf-rfc9381. The upstream implementation is
// licensed MIT OR Apache-2.0.
func TestRustInteropVectors(t *testing.T) {
	vectors := []struct {
		name      string
		seed      string
		publicKey string
		message   string
		proof     string
		output    string
	}{
		{
			name:      "zero_seed",
			seed:      "0000000000000000000000000000000000000000000000000000000000000000",
			publicKey: "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
			message:   "",
			proof:     "d9292f2c17b0a8b7cb17f76b85f5874f5e1eb1533f9706d6c151b31f0910a39fa665132a63acdec7d50cb7019f2760544eb2e6bc28a46339a4fe81fb63b7e91fc87117f774671e9eb7c04b7be7d9a603",
			output:    "eeec527a406225b07b2bd9ed6f4dcf33efe4bbac742475bd0726e7bffa1238db16a5c54ecd1217444bf3773bc16eed29a418069d5059be8bbb0d43ccd653396d",
		},
		{
			name:      "incrementing_seed",
			seed:      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			publicKey: "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
			message:   "6d6c782d676f2d63636c2f736f72746974696f6e2f6e6f6e2d676f2d766563746f722f7631",
			proof:     "cf071e5bfb581cae4d3643f4ce1a90ec0069ddc86f867d6a9fe2607a9513f63d4495beb1d7faf06078033a5f151c20f29924e9497488042b68b9361ff2c9f3473021bdd591bdf252ac7b70d25c10ef0f",
			output:    "10af3d15473556d5809984283bfa2c639ec18876f04254d24587040169d70c533deebb8f5ddfefe5a1254a71b9b95c991743891413f92fdf1bb253266db28487",
		},
		{
			name:      "ff_seed",
			seed:      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			publicKey: "76a1592044a6e4f511265bca73a604d90b0529d1df602be30a19a9257660d1f5",
			message:   "000102ff",
			proof:     "c4ec3e6edda80021f4f8a4f6b5b86645922c609d55e216f6ff3f774a39fb67ebf734116e1f9c5bf92281c0785b81c11b74c63bf58a428d3853ad9a643a3c58325aec56e42393a855618c9bcd8ff7030c",
			output:    "0abb5d351cf24ba53d0ca4e8a579ef22365bc09744138deab43bafed035faac2100edfd6764290a042ebb46aec9460f87a8899b15b7d9fcf1690027e1cb255f1",
		},
	}

	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			privateKey := NewKeyFromSeed(decodeHex(t, vector.seed))
			publicKey := privateKey.Public().(PublicKey)
			if !bytes.Equal(publicKey[:], decodeHex(t, vector.publicKey)) {
				t.Fatalf("public key = %x, want %s", publicKey, vector.publicKey)
			}

			message := decodeHex(t, vector.message)
			proof, err := privateKey.Prove(message)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(proof[:], decodeHex(t, vector.proof)) {
				t.Fatalf("proof = %x, want %s", proof, vector.proof)
			}

			output, err := Verify(publicKey, message, proof)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(output[:], decodeHex(t, vector.output)) {
				t.Fatalf("output = %x, want %s", output, vector.output)
			}
		})
	}
}
