package rfc9381_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"log"

	"github.com/tmc/vrf/rfc9381"
)

func Example() {
	seed := bytes.Repeat([]byte{1}, rfc9381.SeedSize)
	priv := rfc9381.NewKeyFromSeed(seed)
	pub := priv.Public().(rfc9381.PublicKey)

	proof, err := priv.Prove([]byte("message"))
	if err != nil {
		fmt.Println(err)
		return
	}
	output, err := rfc9381.Verify(pub, []byte("message"), proof)
	fmt.Println(err == nil && len(output) == rfc9381.OutputSize)

	// Output:
	// true
}

func ExampleGenerateKey() {
	publicKey, privateKey, err := rfc9381.GenerateKey(rand.Reader)
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
	seed := make([]byte, rfc9381.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		log.Fatal(err)
	}
	privateKey := rfc9381.NewKeyFromSeed(seed)

	proof, err := privateKey.Prove([]byte("hello world"))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Proof size: %d bytes\n", len(proof))
	// Output:
	// Proof size: 80 bytes
}

func ExamplePublicKey_Verify() {
	seed := make([]byte, rfc9381.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		log.Fatal(err)
	}
	privateKey := rfc9381.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(rfc9381.PublicKey)

	message := []byte("hello world")
	proof, err := privateKey.Prove(message)
	if err != nil {
		log.Fatal(err)
	}

	output, err := publicKey.Verify(proof, message)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("VRF output size: %d bytes\n", len(output))
	// Output:
	// VRF output size: 64 bytes
}

// ExampleVerify shows that a proof is bound to the message it was created
// for, and that the failure is reported as ErrVerifyFailed.
func ExampleVerify() {
	seed := make([]byte, rfc9381.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		log.Fatal(err)
	}
	privateKey := rfc9381.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(rfc9381.PublicKey)

	proof, err := privateKey.Prove([]byte("hello world"))
	if err != nil {
		log.Fatal(err)
	}

	output, err := rfc9381.Verify(publicKey, []byte("hello world"), proof)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("VRF output size: %d bytes\n", len(output))

	// The same proof under a different message does not verify.
	if _, err := rfc9381.Verify(publicKey, []byte("goodbye world"), proof); err != nil {
		fmt.Println("different message:", errors.Is(err, rfc9381.ErrVerifyFailed))
	}
	// Output:
	// VRF output size: 64 bytes
	// different message: true
}

func ExampleOutput_PrefixUint64() {
	var out rfc9381.Output
	copy(out[:], []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef})

	fmt.Printf("%016x\n", out.PrefixUint64())
	// Output:
	// 0123456789abcdef
}
