package suitebench

import (
	"testing"

	"github.com/tmc/vrf/draft03"
	"github.com/tmc/vrf/rfc9381"
)

var (
	draftPrivateKey draft03.PrivateKey
	draftProof      draft03.Proof
	draftOutput     draft03.Output
	rfcPrivateKey   rfc9381.PrivateKey
	rfcProof        rfc9381.Proof
	rfcOutput       rfc9381.Output
)

var messageSizes = []struct {
	name string
	size int
}{
	{"0B", 0},
	{"64B", 64},
	{"1KiB", 1024},
	{"4KiB", 4 * 1024},
}

// These benchmarks use identical deterministic fixtures for both suites. Key
// construction, proof construction for Verify, and message allocation happen
// outside the timed region. They measure fixed-input operation latency, not
// throughput over a growing corpus.
func BenchmarkDraft03NewKeyFromSeed(b *testing.B) {
	seed := benchmarkSeed()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		draftPrivateKey = draft03.NewKeyFromSeed(seed[:])
	}
}

func BenchmarkRFC9381NewKeyFromSeed(b *testing.B) {
	seed := benchmarkSeed()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		rfcPrivateKey = rfc9381.NewKeyFromSeed(seed[:])
	}
}

func BenchmarkDraft03Prove(b *testing.B) {
	_, privateKey := draftKey()
	for _, size := range messageSizes {
		b.Run(size.name, func(b *testing.B) {
			message := benchmarkMessage(size.size)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				proof, err := privateKey.Prove(message)
				if err != nil {
					b.Fatal(err)
				}
				draftProof = proof
			}
		})
	}
}

func BenchmarkRFC9381Prove(b *testing.B) {
	_, privateKey := rfcKey()
	for _, size := range messageSizes {
		b.Run(size.name, func(b *testing.B) {
			message := benchmarkMessage(size.size)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				proof, err := privateKey.Prove(message)
				if err != nil {
					b.Fatal(err)
				}
				rfcProof = proof
			}
		})
	}
}

func BenchmarkDraft03Verify(b *testing.B) {
	publicKey, privateKey := draftKey()
	for _, size := range messageSizes {
		b.Run(size.name, func(b *testing.B) {
			message := benchmarkMessage(size.size)
			proof, err := privateKey.Prove(message)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				output, err := draft03.Verify(publicKey, message, proof)
				if err != nil {
					b.Fatal(err)
				}
				draftOutput = output
			}
		})
	}
}

func BenchmarkRFC9381Verify(b *testing.B) {
	publicKey, privateKey := rfcKey()
	for _, size := range messageSizes {
		b.Run(size.name, func(b *testing.B) {
			message := benchmarkMessage(size.size)
			proof, err := privateKey.Prove(message)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				output, err := rfc9381.Verify(publicKey, message, proof)
				if err != nil {
					b.Fatal(err)
				}
				rfcOutput = output
			}
		})
	}
}

func BenchmarkDraft03FullOperation(b *testing.B) {
	publicKey, privateKey := draftKey()
	for _, size := range messageSizes {
		b.Run(size.name, func(b *testing.B) {
			message := benchmarkMessage(size.size)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				proof, err := privateKey.Prove(message)
				if err != nil {
					b.Fatal(err)
				}
				output, err := draft03.Verify(publicKey, message, proof)
				if err != nil {
					b.Fatal(err)
				}
				draftProof = proof
				draftOutput = output
			}
		})
	}
}

func BenchmarkRFC9381FullOperation(b *testing.B) {
	publicKey, privateKey := rfcKey()
	for _, size := range messageSizes {
		b.Run(size.name, func(b *testing.B) {
			message := benchmarkMessage(size.size)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				proof, err := privateKey.Prove(message)
				if err != nil {
					b.Fatal(err)
				}
				output, err := rfc9381.Verify(publicKey, message, proof)
				if err != nil {
					b.Fatal(err)
				}
				rfcProof = proof
				rfcOutput = output
			}
		})
	}
}

func draftKey() (draft03.PublicKey, draft03.PrivateKey) {
	seed := benchmarkSeed()
	privateKey := draft03.NewKeyFromSeed(seed[:])
	return privateKey.Public().(draft03.PublicKey), privateKey
}

func rfcKey() (rfc9381.PublicKey, rfc9381.PrivateKey) {
	seed := benchmarkSeed()
	privateKey := rfc9381.NewKeyFromSeed(seed[:])
	return privateKey.Public().(rfc9381.PublicKey), privateKey
}

func benchmarkSeed() [32]byte {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return seed
}

func benchmarkMessage(size int) []byte {
	message := make([]byte, size)
	for i := range message {
		message[i] = byte(i*31 + 7)
	}
	return message
}
