// Package vrf implements the ECVRF-EDWARDS25519-SHA512-ELL2 verifiable random
// function (suite 0x04) from RFC 9381.
//
// This package is the default entry point: it re-exports
// github.com/tmc/vrf/rfc9381, the final published standard. Its types are
// aliases of the rfc9381 types, so vrf.Proof and rfc9381.Proof are
// interchangeable.
//
// RFC 9381 kept the suite byte 0x04 used by the earlier draft-irtf-cfrg-vrf-03
// but changed hash-to-curve and challenge construction incompatibly. For the
// draft-03 suite used by Algorand's consensus layer, use
// github.com/tmc/vrf/draft03, whose proof and key types are distinct so a
// draft-03 proof cannot be passed to an RFC 9381 verifier by accident.
//
// Basic use:
//
//	seed := make([]byte, vrf.SeedSize)
//	if _, err := rand.Read(seed); err != nil {
//		log.Fatal(err)
//	}
//	priv := vrf.NewKeyFromSeed(seed)
//	pub := priv.PublicKey()
//	proof, err := priv.Prove(message)
//	if err != nil {
//		log.Fatal(err)
//	}
//	output, err := vrf.Verify(pub, message, proof)
package vrf
