package rfc9381

import (
	"bytes"
	"strings"
	"testing"
)

// TestRustInterop checks agreement with an independent Rust implementation of
// this suite on inputs the RFC does not cover. Each vector was reproduced by
// vrf-rfc9381 v0.0.7 (commit 67a36e8af3704d8a6ba926c98d30b8eff1f4c21f),
// https://github.com/OtaK/vrf-rfc9381.
//
// It also verifies these proofs and rejects the draft03 proofs for the same
// keys and messages.
func TestRustInterop(t *testing.T) {
	// A message longer than one SHA-512 block, so that expand_message_xmd
	// produces more than one block.
	long := strings.Repeat("multi-block-message.", 15)

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
			name:      "counting_seed",
			seed:      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			publicKey: "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
			message:   "The quick brown fox jumps over the lazy dog",
			proof:     "02e8a00d92a6a8913541023df15bd085054bdac62e42e0fe8962e79f06e4f97d5cf0e860cec4a8f0d37b9c706fe571c885d575ad03db1bfcbfb5d68cefd20bfc34038efae82de440974cc7861f284a06",
			output:    "2d290b542aaf3cc7b06274ee8f208073b8f780b903851316dfd97881c13d77d1c0e761226941575e6d3c419a61a545427850863292561231e6cd7b77ba56e42f",
		},
		{
			name:      "ff_seed",
			seed:      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			publicKey: "76a1592044a6e4f511265bca73a604d90b0529d1df602be30a19a9257660d1f5",
			message:   "\x00\x01\x02\xff",
			proof:     "c4ec3e6edda80021f4f8a4f6b5b86645922c609d55e216f6ff3f774a39fb67ebf734116e1f9c5bf92281c0785b81c11b74c63bf58a428d3853ad9a643a3c58325aec56e42393a855618c9bcd8ff7030c",
			output:    "0abb5d351cf24ba53d0ca4e8a579ef22365bc09744138deab43bafed035faac2100edfd6764290a042ebb46aec9460f87a8899b15b7d9fcf1690027e1cb255f1",
		},
		{
			name:      "repeated_seed",
			seed:      "4242424242424242424242424242424242424242424242424242424242424242",
			publicKey: "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12",
			message:   "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f",
			proof:     "0d73a54918be23f405f8b837bc1776c6207cf7e62fcd5ad75d3c94230a6061a38b4400f1c8384eacc9e81a75aadcbb91f577c8919c624ebd287b60cd70b5ed7bacdca874d38665e5a6b9dedb570e800f",
			output:    "eb4322df39f812c780a854c8843bf7d9f93f27618892846ed206df3055d0ef5ae0d550fed00e7b8dfa213204e7e6e73eea209de71f1ef2215f73431fbcbe940d",
		},
		{
			name:      "long_message",
			seed:      "0101010101010101010101010101010101010101010101010101010101010101",
			publicKey: "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
			message:   long,
			proof:     "e04cdeff1a87946ed689284ec60cab9e4cff350615188ed52146147804317f7e58499de614418c8954038efe61f288e50deadefc264278b092d4508a412990b1136a80c2e319b4d8362b02bc3c1a640c",
			output:    "467c8612b43d542a3ba6b6729ee54427f96b5f07e1258c007c314931854c79b60f9f8fdad7b79af30250ade054f822ac27745ec5d5c119444a0f473de8980ed6",
		},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			priv := NewKeyFromSeed(decodeHex(t, v.seed))
			pub := priv.PublicKey()
			if !bytes.Equal(pub[:], decodeHex(t, v.publicKey)) {
				t.Fatalf("public key = %x, want %s", pub, v.publicKey)
			}
			proof, err := priv.Prove([]byte(v.message))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(proof[:], decodeHex(t, v.proof)) {
				t.Fatalf("proof = %x, want %s", proof, v.proof)
			}
			out, err := Verify(pub, []byte(v.message), proof)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out[:], decodeHex(t, v.output)) {
				t.Fatalf("output = %x, want %s", out, v.output)
			}
		})
	}
}
