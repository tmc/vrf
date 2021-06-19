package crypto

import (
	"bytes"
	mathrand "math/rand"
	"testing"

	"filippo.io/edwards25519"
)

func BenchmarkCompareCAndGoProofs(b *testing.B) {
	pks := make([]VrfPubkey, b.N)
	sks := make([]VrfPrivkey, b.N)
	strs := make([][]byte, b.N)
	proofs := make([]VrfProof, b.N)
	randSource := mathrand.New(mathrand.NewSource(42))

	for i := 0; i < b.N; i++ {
		validPoint := false
		for !validPoint {
			pks[i], sks[i] = VrfKeygen()
			strs[i] = make([]byte, 100)
			_, err := randSource.Read(strs[i])
			if err != nil {
				panic(err)
			}
			_, err = (&edwards25519.Point{}).SetBytes(sks[i][:32])
			validPoint = err == nil
		}
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var ok bool
		proofs[i], ok = sks[i].proveBytes(strs[i])
		goProof, goOk := sks[i].proveBytesGo(strs[i])

		if ok != goOk {
			b.Errorf("non-matching results: %d sk:%x pk:%x str:%x %v %v\n", i, sks[i][:32], pks[i], strs[i], ok, goOk)
		}
		if bytes.Compare(proofs[i][:], goProof[:]) != 0 {
			b.Errorf("non-matching results: %x %x %x\n", strs[i], proofs[i], goProof)
		}
		// compare verify outputs
		_, cVerify := pks[i].verifyBytes(proofs[i], strs[i])
		_, goVerify := pks[i].verifyBytes(proofs[i], strs[i])
		if cVerify != goVerify {
			b.Errorf("non-matching verify results.")
		}
	}
}
