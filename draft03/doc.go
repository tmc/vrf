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
package draft03
