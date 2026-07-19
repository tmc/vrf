// Package rfc9381 implements ECVRF-EDWARDS25519-SHA512-ELL2 from RFC 9381.
//
// The root package github.com/tmc/vrf re-exports this package as its default.
//
// RFC 9381 is not wire-compatible with the draft-03 suite used by Algorand:
// it changed hash-to-curve and challenge construction. For draft-03 proofs,
// use github.com/tmc/vrf/draft03.
package rfc9381
