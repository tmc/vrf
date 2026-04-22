package vrf_test

import (
	"crypto/rand"
	"fmt"
	"log"

	"github.com/tmc/vrf"
)

func ExampleKeygen() {
	// Generate a random seed
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		log.Fatal(err)
	}

	// Generate VRF key pair from seed
	publicKey, privateKey := vrf.Keygen(seed)

	fmt.Printf("Public key size: %d bytes\n", len(publicKey))
	fmt.Printf("Private key size: %d bytes\n", len(privateKey))
	// Output:
	// Public key size: 32 bytes
	// Private key size: 64 bytes
}

func ExamplePrivateKey_Prove() {
	// Generate keys
	var seed [32]byte
	rand.Read(seed[:])
	_, privateKey := vrf.Keygen(seed)

	// Message to create proof for
	message := []byte("hello world")

	// Generate VRF proof
	proof, err := privateKey.Prove(message)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Proof size: %d bytes\n", len(proof))
	// Output:
	// Proof size: 80 bytes
}

func ExamplePublicKey_Verify() {
	// Generate keys
	var seed [32]byte
	rand.Read(seed[:])
	publicKey, privateKey := vrf.Keygen(seed)

	// Message
	message := []byte("hello world")

	// Generate proof
	proof, err := privateKey.Prove(message)
	if err != nil {
		log.Fatal(err)
	}

	// Verify proof and get VRF output
	output, err := publicKey.Verify(proof, message)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("VRF output size: %d bytes\n", len(output))
	// Output:
	// VRF output size: 64 bytes
}

func ExampleVerify() {
	// Generate keys
	var seed [32]byte
	rand.Read(seed[:])
	publicKey, privateKey := vrf.Keygen(seed)

	// Message
	message := []byte("hello world")

	// Generate proof
	proof, err := privateKey.Prove(message)
	if err != nil {
		log.Fatal(err)
	}

	// Verify proof with the package-level helper.
	output, err := vrf.Verify(publicKey, message, proof)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("VRF output size: %d bytes\n", len(output))
	// Output:
	// VRF output size: 64 bytes
}

func Example() {
	// Generate a random seed for deterministic key generation
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		log.Fatal(err)
	}

	// Generate VRF key pair
	publicKey, privateKey := vrf.Keygen(seed)

	// Message to prove randomness for
	message := []byte("block-12345")

	// Generate VRF proof
	proof, err := privateKey.Prove(message)
	if err != nil {
		log.Fatal(err)
	}

	// Verify proof and get deterministic output
	output, err := vrf.Verify(publicKey, message, proof)
	if err != nil {
		log.Fatal(err)
	}

	// The output is deterministic for a given public key and message
	// Anyone can verify the proof and get the same output
	fmt.Printf("Generated VRF output (%d bytes)\n", len(output))

	// Verify with a different message fails
	_, err = vrf.Verify(publicKey, []byte("different-message"), proof)
	if err != nil {
		fmt.Println("Verification with different message failed (expected)")
	}

	// Output:
	// Generated VRF output (64 bytes)
	// Verification with different message failed (expected)
}
