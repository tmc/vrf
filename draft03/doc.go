// Package draft03 implements the ECVRF-EDWARDS25519-SHA512-ELL2 verifiable
// random function (suite 0x04) from draft-irtf-cfrg-vrf-03.
//
// This is the suite used by Algorand's consensus layer. Tests compare proofs
// and outputs with vectors captured from Algorand's implementation. Those
// vectors establish agreement for the captured cases, not general
// interoperability.
//
// Suite byte 0x04 is shared with the final RFC 9381 suite, but the two changed
// hash-to-curve and challenge construction incompatibly. This package
// implements draft-03; for RFC 9381, use github.com/tmc/vrf (which implements
// RFC 9381) or github.com/tmc/vrf/rfc9381.
//
// # Porting from Algorand's cgo VRF
//
// Algorand's crypto package spells verification as a method on the public key,
// with the proof first:
//
//	ok, out := pk.Verify(proof, message)
//
// That order comes from the ECVRF specification and from libsodium's
// crypto_vrf_verify. This package instead follows crypto/ed25519, taking the
// key first and the message before the proof, and offers only the package-level
// form:
//
//	out, err := draft03.Verify(pub, message, proof)
//
// A failed proof is an error here rather than a false result. Code porting from
// the cgo API can bridge the two with a small adapter; the argument types
// differ, so a call left in the old order fails to compile rather than
// silently verifying the wrong thing.
package draft03
