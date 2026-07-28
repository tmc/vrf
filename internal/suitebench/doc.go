// Package suitebench holds the checks and benchmarks that need both suites at
// once, so that neither draft03 nor rfc9381 has to import the other.
//
// The tests cover what only a cross-suite view can: that the two suites agree
// on their sizes and parse-error categories, that their suite strings differ,
// and that each rejects the other's proofs. That last check is the reason this
// package exists. Both suites carry suite byte 0x04 and use identical key and
// proof encodings, so one suite's proof parses cleanly as the other's and is
// rejected only by the challenge arithmetic.
package suitebench
