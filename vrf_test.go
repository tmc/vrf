package vrf

import (
	"bytes"
	"crypto/rand"
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

	outputPkg, err := Verify(pk, message, proof)
	if err != nil {
		t.Fatalf("Failed to verify proof with package-level helper: %v", err)
	}
	if !bytes.Equal(output1[:], outputPkg[:]) {
		t.Fatal("Method and package-level verification returned different outputs")
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
	_, err = Verify(pk, wrongMessage, proof)
	if err == nil {
		t.Error("Expected package-level verification to fail for wrong message")
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
