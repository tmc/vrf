// Package rfc9381 implements ECVRF-EDWARDS25519-SHA512-ELL2 from RFC 9381.
//
// It is not wire-compatible with the draft-03 suite used by Algorand: RFC 9381
// changed hash-to-curve and challenge construction. For draft-03 proofs, use
// github.com/tmc/vrf or github.com/tmc/vrf/draft03.
package rfc9381
