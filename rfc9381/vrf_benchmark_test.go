package rfc9381

import (
	"crypto/sha512"
	"testing"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
)

var (
	benchmarkPrivateKey PrivateKey
	benchmarkProof      Proof
	benchmarkOutput     Output
	benchmarkBytes      []byte
	benchmarkPoint      *edwards25519.Point
	benchmarkScalar     *edwards25519.Scalar
	benchmarkField      *field.Element
)

// The exported-operation benchmarks reuse deterministic valid inputs and keep
// fixture construction outside the timer. The internal benchmarks diagnose
// profiles; they are not substitutes for exported-operation measurements.
var benchmarkMessageSizes = []struct {
	name string
	size int
}{
	{"0B", 0},
	{"64B", 64},
	{"1KiB", 1024},
	{"4KiB", 4 * 1024},
}

func BenchmarkRFC9381NewKeyFromSeed(b *testing.B) {
	seed := benchmarkSeed()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		benchmarkPrivateKey = NewKeyFromSeed(seed[:])
	}
}

func BenchmarkRFC9381Prove(b *testing.B) {
	_, priv := benchmarkKey(b)
	for _, size := range benchmarkMessageSizes {
		b.Run(size.name, func(b *testing.B) {
			message := benchmarkMessage(size.size)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				proof, err := priv.Prove(message)
				if err != nil {
					b.Fatal(err)
				}
				benchmarkProof = proof
			}
		})
	}
}

func BenchmarkRFC9381Verify(b *testing.B) {
	pub, priv := benchmarkKey(b)
	for _, size := range benchmarkMessageSizes {
		b.Run(size.name, func(b *testing.B) {
			message := benchmarkMessage(size.size)
			proof, err := priv.Prove(message)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				output, err := Verify(pub, message, proof)
				if err != nil {
					b.Fatal(err)
				}
				benchmarkOutput = output
			}
		})
	}
}

func BenchmarkRFC9381FullOperation(b *testing.B) {
	pub, priv := benchmarkKey(b)
	for _, size := range benchmarkMessageSizes {
		b.Run(size.name, func(b *testing.B) {
			message := benchmarkMessage(size.size)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				proof, err := priv.Prove(message)
				if err != nil {
					b.Fatal(err)
				}
				output, err := Verify(pub, message, proof)
				if err != nil {
					b.Fatal(err)
				}
				benchmarkProof = proof
				benchmarkOutput = output
			}
		})
	}
}

func BenchmarkRFC9381ProofToHash(b *testing.B) {
	_, priv := benchmarkKey(b)
	proof, err := priv.Prove(benchmarkMessage(64))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		output, err := proofToHash(proof[:])
		if err != nil {
			b.Fatal(err)
		}
		benchmarkBytes = output[:]
	}
}

func BenchmarkRFC9381InternalEncodeToCurve(b *testing.B) {
	pub, _ := benchmarkKey(b)
	Y := new(edwards25519.Point)
	if _, err := Y.SetBytes(pub[:]); err != nil {
		b.Fatal(err)
	}
	for _, size := range benchmarkMessageSizes {
		b.Run(size.name, func(b *testing.B) {
			message := benchmarkMessage(size.size)
			var point edwards25519.Point
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if err := encodeToCurve(&point, Y, message); err != nil {
					b.Fatal(err)
				}
			}
			benchmarkPoint = &point
		})
	}
}

func BenchmarkRFC9381InternalHashToField(b *testing.B) {
	pub, _ := benchmarkKey(b)
	for _, size := range benchmarkMessageSizes {
		b.Run(size.name, func(b *testing.B) {
			message := benchmarkMessage(size.size)
			var element field.Element
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if err := hashToField(&element, pub[:], message); err != nil {
					b.Fatal(err)
				}
			}
			benchmarkField = &element
		})
	}
}

func BenchmarkRFC9381InternalExpandMessageXMD(b *testing.B) {
	for _, size := range benchmarkMessageSizes {
		b.Run(size.name, func(b *testing.B) {
			message := benchmarkMessage(PublicKeySize + size.size)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				benchmarkBytes = expandMessageXMD(message, hashToCurveDST, 48)
			}
		})
	}
}

func BenchmarkRFC9381InternalMapToCurve(b *testing.B) {
	var element field.Element
	if err := hashToField(&element, benchmarkMessage(64)); err != nil {
		b.Fatal(err)
	}
	var point edwards25519.Point
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := mapToCurve(&point, &element); err != nil {
			b.Fatal(err)
		}
	}
	benchmarkPoint = &point
}

func BenchmarkRFC9381InternalNonceGeneration(b *testing.B) {
	_, priv := benchmarkKey(b)
	var Y edwards25519.Point
	var x edwards25519.Scalar
	var truncatedHash [32]byte
	if err := priv.expand(&Y, &x, &truncatedHash); err != nil {
		b.Fatal(err)
	}
	var H edwards25519.Point
	if err := encodeToCurve(&H, &Y, benchmarkMessage(64)); err != nil {
		b.Fatal(err)
	}
	var scalar edwards25519.Scalar
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		nonceGeneration(&scalar, truncatedHash, &H)
	}
	benchmarkScalar = &scalar
}

func BenchmarkRFC9381InternalChallenge(b *testing.B) {
	_, priv := benchmarkKey(b)
	var Y edwards25519.Point
	var x edwards25519.Scalar
	var truncatedHash [32]byte
	if err := priv.expand(&Y, &x, &truncatedHash); err != nil {
		b.Fatal(err)
	}
	var H edwards25519.Point
	if err := encodeToCurve(&H, &Y, benchmarkMessage(64)); err != nil {
		b.Fatal(err)
	}
	Gamma := new(edwards25519.Point).ScalarMult(&x, &H)
	var scalar edwards25519.Scalar
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		challenge(&scalar, &Y, &H, Gamma, &Y, &H)
	}
	benchmarkScalar = &scalar
}

func BenchmarkRFC9381InternalDecodeProof(b *testing.B) {
	_, priv := benchmarkKey(b)
	proof, err := priv.Prove(benchmarkMessage(64))
	if err != nil {
		b.Fatal(err)
	}
	var Gamma edwards25519.Point
	var s edwards25519.Scalar
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, err := decodeProof(&Gamma, &s, proof[:])
		if err != nil {
			b.Fatal(err)
		}
	}
	benchmarkPoint = &Gamma
	benchmarkScalar = &s
}

func benchmarkKey(b *testing.B) (PublicKey, PrivateKey) {
	b.Helper()
	seed := benchmarkSeed()
	priv := NewKeyFromSeed(seed[:])
	pub, ok := priv.Public().(PublicKey)
	if !ok {
		b.Fatal("private key returned unexpected public key type")
	}
	return pub, priv
}

func benchmarkSeed() [SeedSize]byte {
	return sha512.Sum512_256([]byte("github.com/tmc/vrf/rfc9381 benchmark seed"))
}

func benchmarkMessage(size int) []byte {
	message := make([]byte, size)
	for i := range message {
		message[i] = byte(i*31 + 7)
	}
	return message
}
