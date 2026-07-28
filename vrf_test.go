package vrf_test

import (
	"bytes"
	"testing"

	"github.com/tmc/vrf"
	"github.com/tmc/vrf/rfc9381"
)

// The root package re-exports rfc9381. These tests confirm the alias is wired
// to the RFC 9381 suite (not draft-03) and that proofs round-trip through the
// re-exported API.

func TestRootIsRFC9381(t *testing.T) {
	if vrf.SuiteID != rfc9381.SuiteID {
		t.Fatalf("SuiteID = %#x, want rfc9381 %#x", vrf.SuiteID, rfc9381.SuiteID)
	}
	// SuiteID cannot show which suite this is: draft03 uses 0x04 too. That the
	// root is RFC 9381 and not draft-03 is what TestRootProofMatchesRFC9381
	// establishes, by comparing proof bytes.
}

func TestRootProofMatchesRFC9381(t *testing.T) {
	seed := bytes.Repeat([]byte{0x24}, vrf.SeedSize)
	message := []byte("root alias smoke test")

	// Prove and verify through the root package.
	priv := vrf.NewKeyFromSeed(seed)
	pub := priv.PublicKey()
	if !pub.Equal(priv.Public().(vrf.PublicKey)) {
		t.Fatal("PublicKey and Public returned different keys")
	}
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
