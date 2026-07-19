package suitebench

import (
	"errors"
	"testing"

	"github.com/tmc/vrf/draft03"
	"github.com/tmc/vrf/rfc9381"
)

func TestAPISizesMatch(t *testing.T) {
	tests := []struct {
		name  string
		draft int
		rfc   int
	}{
		{"public key", draft03.PublicKeySize, rfc9381.PublicKeySize},
		{"private key", draft03.PrivateKeySize, rfc9381.PrivateKeySize},
		{"seed", draft03.SeedSize, rfc9381.SeedSize},
		{"proof", draft03.ProofSize, rfc9381.ProofSize},
		{"output", draft03.OutputSize, rfc9381.OutputSize},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.draft != test.rfc {
				t.Fatalf("draft-03 size = %d, RFC 9381 size = %d", test.draft, test.rfc)
			}
		})
	}
	if draft03.SuiteString == rfc9381.SuiteString {
		t.Fatalf("suite strings are both %q", draft03.SuiteString)
	}
}

func TestParseErrorCategoriesMatch(t *testing.T) {
	if _, err := draft03.ParsePublicKey(make([]byte, draft03.PublicKeySize-1)); !errors.Is(err, draft03.ErrInvalidPublicKey) {
		t.Fatalf("draft-03 ParsePublicKey error = %v", err)
	}
	if _, err := rfc9381.ParsePublicKey(make([]byte, rfc9381.PublicKeySize-1)); !errors.Is(err, rfc9381.ErrInvalidPublicKey) {
		t.Fatalf("RFC 9381 ParsePublicKey error = %v", err)
	}
	if _, err := draft03.ParseProof(make([]byte, draft03.ProofSize-1)); !errors.Is(err, draft03.ErrInvalidProof) {
		t.Fatalf("draft-03 ParseProof error = %v", err)
	}
	if _, err := rfc9381.ParseProof(make([]byte, rfc9381.ProofSize-1)); !errors.Is(err, rfc9381.ErrInvalidProof) {
		t.Fatalf("RFC 9381 ParseProof error = %v", err)
	}
}

func TestSuitesRejectEachOthersProofs(t *testing.T) {
	seed := benchmarkSeed()
	message := benchmarkMessage(64)

	draftPrivateKey := draft03.NewKeyFromSeed(seed[:])
	draftPublicKey := draftPrivateKey.Public().(draft03.PublicKey)
	draftProof, err := draftPrivateKey.Prove(message)
	if err != nil {
		t.Fatal(err)
	}

	rfcPrivateKey := rfc9381.NewKeyFromSeed(seed[:])
	rfcPublicKey := rfcPrivateKey.Public().(rfc9381.PublicKey)
	rfcProof, err := rfcPrivateKey.Prove(message)
	if err != nil {
		t.Fatal(err)
	}

	var parsedRFCProof rfc9381.Proof
	copy(parsedRFCProof[:], draftProof[:])
	if _, err := rfc9381.Verify(rfcPublicKey, message, parsedRFCProof); !errors.Is(err, rfc9381.ErrVerifyFailed) {
		t.Fatalf("RFC 9381 verification of draft-03 proof error = %v, want %v", err, rfc9381.ErrVerifyFailed)
	}

	var parsedDraftProof draft03.Proof
	copy(parsedDraftProof[:], rfcProof[:])
	if _, err := draft03.Verify(draftPublicKey, message, parsedDraftProof); !errors.Is(err, draft03.ErrVerifyFailed) {
		t.Fatalf("draft-03 verification of RFC 9381 proof error = %v, want %v", err, draft03.ErrVerifyFailed)
	}
}
