package draft03

import (
	"bytes"
	"strings"
	"testing"
)

// TestRustInterop checks agreement with two independent Rust implementations
// of this suite. Cardano uses draft-03 ECVRF-ED25519-SHA512-Elligator2 too,
// having adopted it from Algorand's libsodium fork, so its Rust crates are
// independent implementations of what this package does.
//
// Each vector was reproduced by both:
//
//   - cardano-crypto v1.0.8, https://github.com/FractionEstate/cardano-crypto
//   - amaru-vrf-dalek v0.1.0, https://github.com/pragma-org/amaru
//
// Both also verify these proofs, verify Algorand's own vectors in
// vrf_parity_test.go, and reject the rfc9381 proofs for the same keys and
// messages.
func TestRustInterop(t *testing.T) {
	// A message longer than one SHA-512 block.
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
			name:      "rfc_b4_example_19",
			seed:      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
			publicKey: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
			message:   "",
			proof:     "b6b4699f87d56126c9117a7da55bd0085246f4c56dbc95d20172612e9d38e8d7ca65e573a126ed88d4e30a46f80a666854d675cf3ba81de0de043c3774f061560f55edc256a787afe701677c0f602900",
			output:    "5b49b554d05c0cd5a5325376b3387de59d924fd1e13ded44648ab33c21349a603f25b84ec5ed887995b33da5e3bfcb87cd2f64521c4c62cf825cffabbe5d31cc",
		},
		{
			name:      "rfc_b4_example_20",
			seed:      "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
			publicKey: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
			message:   "r",
			proof:     "ae5b66bdf04b4c010bfe32b2fc126ead2107b697634f6f7337b9bff8785ee111200095ece87dde4dbe87343f6df3b107d91798c8a7eb1245d3bb9c5aafb093358c13e6ae1111a55717e895fd15f99f07",
			output:    "94f4487e1b2fec954309ef1289ecb2e15043a2461ecc7b2ae7d4470607ef82eb1cfa97d84991fe4a7bfdfd715606bc27e2967a6c557cfb5875879b671740b7d8",
		},
		{
			name:      "rfc_b4_example_21",
			seed:      "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
			publicKey: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
			message:   "\xaf\x82",
			proof:     "dfa2cba34b611cc8c833a6ea83b8eb1bb5e2ef2dd1b0c481bc42ff36ae7847f6ab52b976cfd5def172fa412defde270c8b8bdfbaae1c7ece17d9833b1bcf31064fff78ef493f820055b561ece45e1009",
			output:    "2031837f582cd17a9af9e0c7ef5a6540e3453ed894b62c293686ca3c1e319dde9d0aa489a4b59a9594fc2328bc3deff3c8a0929a369a72b1180a596e016b5ded",
		},
		{
			name:      "zero_seed",
			seed:      "0000000000000000000000000000000000000000000000000000000000000000",
			publicKey: "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
			message:   "",
			proof:     "3af639535e4eca74dd777e0df983987b6b2c172363f6fdb442011883bc5c5b307e00299477c8702369ce2a4196ac3ac8fec3c4c28471386e5e74a9bcca7bca19741c0447c0b7c857b8137432fac44904",
			output:    "64ce2d39a78eec9920d1f0cd2212380907e9415c59e67e7440a7a312430dca32ed746d894b5676c21a1eb63c77f59b44c2bceec92624652ea073c14cd6622bee",
		},
		{
			name:      "ff_seed",
			seed:      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			publicKey: "76a1592044a6e4f511265bca73a604d90b0529d1df602be30a19a9257660d1f5",
			message:   "\x00\x01\x02\xff",
			proof:     "00f86146bac3b73ad5428e40c65c23ac3df9379ae8f64ce11fcb765c11d9367f0b15c70aceb5fc0fe4a255e1301d34a19d41cb46640aacfb8f09fcefd33e81959aa89e45d0694c4b0f4039c264a87d0c",
			output:    "b3635ba10cd63b865a997180afe669bfe2c7a220e285718121d890c4c54ea204ae855999129ae352a3aab4a504e614825c63700e9a95fb63d2f7bfd61f2af24f",
		},
		{
			name:      "counting_seed",
			seed:      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			publicKey: "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
			message:   "The quick brown fox jumps over the lazy dog",
			proof:     "a5b934e3ff77f40cbf443652be66e7aebaaed13935d743ceefff463d554ea2ff7c9b8a19393d17d8d23e01fdca6f2ab08c6733c262e58dd5b737daa10ad68c81d255cd6a8c26b39b7deacb8a82ea7205",
			output:    "6b671f6ee794d34ab579185db06d05ff47def6448a427a6302cd80495b7edd9475ce288374ecfa71d92e0e53220a07454978806da338e6e3e255a0940f88014c",
		},
		{
			name:      "repeated_seed",
			seed:      "4242424242424242424242424242424242424242424242424242424242424242",
			publicKey: "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12",
			message:   "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f",
			proof:     "b3d607c9b2a69967844d2d67e3f00e543ed6c4dc4353a84cf0bf10f115c8d20144205535e289e00b5cedd8dd0912912629dc2390d3408cfefca30d600f4110b2c4c30928b36b143255080ffb85247c0d",
			output:    "98cbdbb69cb76868f03b4fe6b2205a7ddd5954fd0f54f22dafb3a994a8741ab97c40191dd1206b763535ec73d001027d1305345437ddbd6ddb980f2d86b28d1b",
		},
		{
			name:      "long_message",
			seed:      "0101010101010101010101010101010101010101010101010101010101010101",
			publicKey: "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
			message:   long,
			proof:     "0d79025e004d050e1a24bde497bcb8907a61b385ed5ad7de562f6b262fbc5806d575dc0c431eb831dc76b14432f0e391b6b026aee421f9a49ffdd244c7a05f22eab666f6ad699bf0316822b49bbd7b0b",
			output:    "f6b42ffc0377cc31a8d1fa2e91074fdba87cce58ec8aaf00ef9c9eea72fbb8ff9f66df2c47739d92ff67d581ea00aa9ab11d6a2db2bdcb3ef864e650b6066bee",
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
