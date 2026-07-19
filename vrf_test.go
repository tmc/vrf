package vrf_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tmc/vrf"
	"github.com/tmc/vrf/rfc9381"
)

// The root package re-exports rfc9381. These tests confirm the alias is wired
// to the RFC 9381 suite (not draft-03) and that proofs round-trip through the
// re-exported API.

func TestRootIsRFC9381(t *testing.T) {
	if vrf.SuiteString != rfc9381.SuiteString {
		t.Fatalf("SuiteString = %q, want rfc9381 %q", vrf.SuiteString, rfc9381.SuiteString)
	}
	if !strings.Contains(vrf.SuiteString, "RFC 9381") {
		t.Fatalf("SuiteString = %q, want it to name RFC 9381", vrf.SuiteString)
	}
}

func TestRootProofMatchesRFC9381(t *testing.T) {
	seed := bytes.Repeat([]byte{0x24}, vrf.SeedSize)
	message := []byte("root alias smoke test")

	// Prove and verify through the root package.
	priv := vrf.NewKeyFromSeed(seed)
	pub := priv.Public().(vrf.PublicKey)
	proof, err := priv.Prove(message)
	if err != nil {
		t.Fatal(err)
	}
	out, err := vrf.Verify(pub, message, proof)
	if err != nil {
		t.Fatal(err)
	}

	// The same inputs through rfc9381 must produce byte-identical results,
	// proving the root is the RFC 9381 suite and the alias types coincide.
	rfcPriv := rfc9381.NewKeyFromSeed(seed)
	rfcProof, err := rfcPriv.Prove(message)
	if err != nil {
		t.Fatal(err)
	}
	rfcOut, err := rfc9381.Verify(rfcPriv.Public().(rfc9381.PublicKey), message, rfcProof)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(proof[:], rfcProof[:]) {
		t.Fatalf("root proof != rfc9381 proof")
	}
	if !bytes.Equal(out[:], rfcOut[:]) {
		t.Fatalf("root output != rfc9381 output")
	}
}
