// Package draft03 implements ECVRF-EDWARDS25519-SHA512-ELL2 (suite 0x04) from
// draft-irtf-cfrg-vrf-03, the suite used by Algorand's consensus layer.
//
// It is a named import path for the same implementation exported by
// github.com/tmc/vrf. Proofs and outputs are byte-identical to Algorand's
// libsodium fork, verified against parity vectors in the root package. Use this
// path when code must make the draft-03 suite explicit at the import site.
//
// For the final RFC 9381 suite, which is not wire-compatible with draft-03, use
// github.com/tmc/vrf/rfc9381.
package draft03
