// Package vrf implements ECVRF-EDWARDS25519-SHA512-ELL2 (suite 0x04).
//
// This package follows draft-irtf-cfrg-vrf-03, matching Algorand's
// implementation. For an explicit Algorand import path, use
// github.com/tmc/vrf/algorand. For the final RFC 9381 suite, use
// github.com/tmc/vrf/rfc9381.
//
// Basic use:
//
//	seed := make([]byte, vrf.SeedSize)
//	if _, err := rand.Read(seed); err != nil {
//		log.Fatal(err)
//	}
//	priv := vrf.NewKeyFromSeed(seed)
//	pub := priv.Public().(vrf.PublicKey)
//	proof, err := priv.Prove(message)
//	if err != nil {
//		log.Fatal(err)
//	}
//	output, err := vrf.Verify(pub, message, proof)
package vrf
