package draft03_test

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/tmc/vrf/draft03"
)

func ExampleParsePublicKey() {
	seed := make([]byte, draft03.SeedSize)
	privateKey := draft03.NewKeyFromSeed(seed)

	wire, err := hex.DecodeString("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29")
	if err != nil {
		log.Fatal(err)
	}
	parsed, err := draft03.ParsePublicKey(wire)
	if err != nil {
		log.Fatal(err)
	}

	proof, err := privateKey.Prove([]byte("message"))
	if err != nil {
		log.Fatal(err)
	}
	output, err := draft03.Verify(parsed, []byte("message"), proof)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(output))
	// Output:
	// 64
}

func ExampleOutput_PrefixUint64() {
	var out draft03.Output
	copy(out[:], []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef})

	fmt.Printf("%016x\n", out.PrefixUint64())
	// Output:
	// 0123456789abcdef
}

func ExampleGenerateKey() {
	publicKey, privateKey, err := draft03.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Public key size: %d bytes\n", len(publicKey))
	fmt.Printf("Private key size: %d bytes\n", len(privateKey))
	// Output:
	// Public key size: 32 bytes
	// Private key size: 64 bytes
}

func ExamplePrivateKey_Prove() {
	// Generate keys
	seed := make([]byte, draft03.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		log.Fatal(err)
	}
	privateKey := draft03.NewKeyFromSeed(seed)

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
	seed := make([]byte, draft03.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		log.Fatal(err)
	}
	privateKey := draft03.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(draft03.PublicKey)

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
	seed := make([]byte, draft03.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		log.Fatal(err)
	}
	privateKey := draft03.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(draft03.PublicKey)

	// Message
	message := []byte("hello world")

	// Generate proof
	proof, err := privateKey.Prove(message)
	if err != nil {
		log.Fatal(err)
	}

	// Verify proof with the package-level helper.
	output, err := draft03.Verify(publicKey, message, proof)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("VRF output size: %d bytes\n", len(output))
	// Output:
	// VRF output size: 64 bytes
}

func Example() {
	// Generate a random seed for deterministic key generation
	seed := make([]byte, draft03.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		log.Fatal(err)
	}

	// Generate VRF key pair
	privateKey := draft03.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(draft03.PublicKey)

	// Message to prove randomness for
	message := []byte("block-12345")

	// Generate VRF proof
	proof, err := privateKey.Prove(message)
	if err != nil {
		log.Fatal(err)
	}

	// Verify proof and get deterministic output
	output, err := draft03.Verify(publicKey, message, proof)
	if err != nil {
		log.Fatal(err)
	}

	// The output is deterministic for a given public key and message
	// Anyone can verify the proof and get the same output
	fmt.Printf("Generated VRF output (%d bytes)\n", len(output))

	// Verify with a different message fails
	_, err = draft03.Verify(publicKey, []byte("different-message"), proof)
	if err != nil {
		fmt.Println("Verification with different message failed (expected)")
	}

	// Output:
	// Generated VRF output (64 bytes)
	// Verification with different message failed (expected)
}
