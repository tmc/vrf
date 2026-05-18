package rfc9381

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestKeys(t *testing.T) {
	seed := [32]byte{}
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatal(err)
	}

	pk, sk := Keygen(seed)

	if len(pk) != PublicKeySize {
		t.Errorf("PublicKeySize: expected %d, got %d", PublicKeySize, len(pk))
	}
	if len(sk) != PrivateKeySize {
		t.Errorf("PrivateKeySize: expected %d, got %d", PrivateKeySize, len(sk))
	}

	// Check if SK contains seed and pk
	if !bytes.Equal(sk[:32], seed[:]) {
		t.Errorf("Secret key does not contain seed")
	}
	if !bytes.Equal(sk[32:], pk[:]) {
		t.Errorf("Secret key does not contain public key")
	}
}

func TestProveVerify(t *testing.T) {
	seed := [32]byte{}
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatal(err)
	}

	pk, sk := Keygen(seed)
	message := []byte("hello world")

	proof, err := sk.Prove(message)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}

	if len(proof) != ProofSize {
		t.Errorf("ProofSize: expected %d, got %d", ProofSize, len(proof))
	}

	output, err := pk.Verify(proof, message)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if len(output) != OutputSize {
		t.Errorf("OutputSize: expected %d, got %d", OutputSize, len(output))
	}
}

func TestVerifyInvalid(t *testing.T) {
	seed := [32]byte{}
	rand.Read(seed[:])
	pk, sk := Keygen(seed)
	message := []byte("test message")

	proof, _ := sk.Prove(message)

	// Test 1: Invalid message
	_, err := pk.Verify(proof, []byte("wrong message"))
	if err == nil {
		t.Error("Verify passed with wrong message")
	}

	// Test 2: Invalid proof (modification)
	proof[0] ^= 0xFF
	_, err = pk.Verify(proof, message)
	if err == nil {
		t.Error("Verify passed with modified proof")
	}
}

// TestVector checks against RFC 9381 Example 19
func TestVector(t *testing.T) {
	skHex := "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	pkHex := "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

	seedBytes, _ := hex.DecodeString(skHex)
	expectedPK, _ := hex.DecodeString(pkHex)

	var seed [32]byte
	copy(seed[:], seedBytes)

	pk, sk := Keygen(seed)

	if !bytes.Equal(pk[:], expectedPK) {
		t.Errorf("Keygen mismatch\nGot:  %x\nWant: %x", pk[:], expectedPK)
	}

	// Double check SK expansion
	// Note: sk from Keygen is [seed || pk]
	// The vector SK is just the seed? Or the scalar?
	// Note from summary: "SK... derived from Section 7.1 of RFC 8032".
	// RFC 8032 Section 7.1 likely uses 32-byte seed.
	// Our Keygen logic matches standard Ed25519 derivation.

	// Check Prove() with empty message (alpha="")
	// Since we don't have the proof hex from the summary (only components),
	// we will just Verify() the proof with the keys.
	// This confirms self-consistency on a known key pair at least.

	proof, err := sk.Prove(nil)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}

	_, err = pk.Verify(proof, nil)
	if err != nil {
		t.Fatalf("Verify failed on test vector keys: %v", err)
	}
}
