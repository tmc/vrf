package vrf

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestVRFBasicOperation(t *testing.T) {
	// Generate a random seed
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatal(err)
	}

	// Generate key pair
	pk, sk := Keygen(seed)

	// Test message
	message := []byte("hello world")

	// Generate proof
	proof, err := sk.Prove(message)
	if err != nil {
		t.Fatalf("Failed to generate proof: %v", err)
	}

	// Verify proof
	output1, err := pk.Verify(proof, message)
	if err != nil {
		t.Fatalf("Failed to verify proof: %v", err)
	}

	// Verify again to ensure deterministic output
	output2, err := pk.Verify(proof, message)
	if err != nil {
		t.Fatalf("Failed to verify proof second time: %v", err)
	}

	// Outputs should be identical
	if !bytes.Equal(output1[:], output2[:]) {
		t.Error("VRF outputs are not deterministic")
	}

	// Wrong message should fail verification
	wrongMessage := []byte("wrong message")
	_, err = pk.Verify(proof, wrongMessage)
	if err == nil {
		t.Error("Expected verification to fail for wrong message")
	}
}

func TestVRFDeterministic(t *testing.T) {
	seed := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

	// Generate same key pair twice
	pk1, sk1 := Keygen(seed)
	pk2, sk2 := Keygen(seed)

	// Keys should be identical
	if !bytes.Equal(pk1[:], pk2[:]) {
		t.Error("Public keys are not deterministic")
	}
	if !bytes.Equal(sk1[:], sk2[:]) {
		t.Error("Private keys are not deterministic")
	}

	message := []byte("test message")

	// Generate proofs
	proof1, err := sk1.Prove(message)
	if err != nil {
		t.Fatal(err)
	}
	proof2, err := sk2.Prove(message)
	if err != nil {
		t.Fatal(err)
	}

	// Proofs should be identical
	if !bytes.Equal(proof1[:], proof2[:]) {
		t.Error("Proofs are not deterministic")
	}

	// Outputs should be identical
	output1, err := pk1.Verify(proof1, message)
	if err != nil {
		t.Fatal(err)
	}
	output2, err := pk2.Verify(proof2, message)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(output1[:], output2[:]) {
		t.Error("VRF outputs are not deterministic")
	}
}

func TestVRFInvalidInputs(t *testing.T) {
	var seed [32]byte
	rand.Read(seed[:])
	pk, sk := Keygen(seed)
	message := []byte("test")

	// Valid proof first
	validProof, err := sk.Prove(message)
	if err != nil {
		t.Fatal(err)
	}

	// Test invalid proof size
	invalidProof := Proof{}
	copy(invalidProof[:], validProof[:])
	invalidProof[0] ^= 1 // Corrupt first byte

	_, err = pk.Verify(invalidProof, message)
	if err == nil {
		t.Error("Expected verification to fail for corrupted proof")
	}
}

func BenchmarkVRFProve(b *testing.B) {
	var seed [32]byte
	rand.Read(seed[:])
	_, sk := Keygen(seed)
	message := []byte("benchmark message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sk.Prove(message)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVRFVerify(b *testing.B) {
	var seed [32]byte
	rand.Read(seed[:])
	pk, sk := Keygen(seed)
	message := []byte("benchmark message")

	proof, err := sk.Prove(message)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := pk.Verify(proof, message)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// TestRFC9381Vectors tests against the RFC 9381 test vectors for ECVRF-EDWARDS25519-SHA512-ELL2
func TestRFC9381Vectors(t *testing.T) {
	tests := []struct {
		name    string
		sk      string
		pk      string
		alpha   string
		pi      string
		beta    string
	}{
		{
			name:  "RFC 9381 Example 19 (empty message)",
			sk:    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
			pk:    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
			alpha: "",
			pi:    "7d9c633ffeee27349264cf5c667579fc583b4bda63ab71d001f89c10003ab46f14adf9a3cd8b8412d9038531e865c341cafa73589b023d14311c331a9ad15ff2fb37831e00f0acaa6d73bc9997b06501",
			beta:  "9d574bf9b8302ec0fc1e21c3ec5368269527b87b462ce36dab2d14ccf80c53cccf6758f058c5b1c856b116388152bbe509ee3b9ecfe63d93c3b4346c1fbc6c54",
		},
		{
			name:  "RFC 9381 Example 20 (1 byte message)",
			sk:    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
			pk:    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
			alpha: "72",
			pi:    "47b327393ff2dd81336f8a2ef10339112401253b3c714eeda879f12c509072ef055b48372bb82efbdce8e10c8cb9a2f9d60e93908f93df1623ad78a86a028d6bc064dbfc75a6a57379ef855dc6733801",
			beta:  "38561d6b77b71d30eb97a062168ae12b667ce5c28caccdf76bc88e093e4635987cd96814ce55b4689b3dd2947f80e59aac7b7675f8083865b46c89b2ce9cc735",
		},
		{
			name:  "RFC 9381 Example 21 (2 byte message)",
			sk:    "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
			pk:    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
			alpha: "af82",
			pi:    "926e895d308f5e328e7aa159c06eddbe56d06846abf5d98c2512235eaa57fdce35b46edfc655bc828d44ad09d1150f31374e7ef73027e14760d42e77341fe05467bb286cc2c9d7fde29120a0b2320d04",
			beta:  "121b7f9b9aaaa29099fc04a94ba52784d44eac976dd1a3cca458733be5cd090a7b5fbd148444f17f8daf1fb55cb04b1ae85a626e30a54b4b0f8abf4a43314a58",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Decode hex inputs
			skBytes, err := decodeHex(tt.sk)
			if err != nil {
				t.Fatalf("Failed to decode SK: %v", err)
			}
			pkBytes, err := decodeHex(tt.pk)
			if err != nil {
				t.Fatalf("Failed to decode PK: %v", err)
			}
			alphaBytes, err := decodeHex(tt.alpha)
			if err != nil {
				t.Fatalf("Failed to decode alpha: %v", err)
			}
			expectedPi, err := decodeHex(tt.pi)
			if err != nil {
				t.Fatalf("Failed to decode pi: %v", err)
			}
			expectedBeta, err := decodeHex(tt.beta)
			if err != nil {
				t.Fatalf("Failed to decode beta: %v", err)
			}

			// Construct keys from test vectors
			var seed [32]byte
			copy(seed[:], skBytes)
			pk, sk := Keygen(seed)

			// Verify public key matches
			if !bytes.Equal(pk[:], pkBytes) {
				t.Errorf("Public key mismatch\nGot:  %x\nWant: %x", pk, pkBytes)
			}

			// Generate proof
			proof, err := sk.Prove(alphaBytes)
			if err != nil {
				t.Fatalf("Failed to prove: %v", err)
			}

			// Verify proof matches expected
			if !bytes.Equal(proof[:], expectedPi) {
				t.Errorf("Proof mismatch\nGot:  %x\nWant: %x", proof, expectedPi)
			}

			// Verify and get output
			output, err := pk.Verify(proof, alphaBytes)
			if err != nil {
				t.Fatalf("Failed to verify: %v", err)
			}

			// Verify output matches expected beta
			if !bytes.Equal(output[:], expectedBeta) {
				t.Errorf("Output mismatch\nGot:  %x\nWant: %x", output, expectedBeta)
			}
		})
	}
}

func decodeHex(s string) ([]byte, error) {
	if s == "" {
		return []byte{}, nil
	}
	result := make([]byte, len(s)/2)
	for i := 0; i < len(result); i++ {
		var b byte
		_, err := fmt.Sscanf(s[i*2:i*2+2], "%02x", &b)
		if err != nil {
			return nil, err
		}
		result[i] = b
	}
	return result, nil
}