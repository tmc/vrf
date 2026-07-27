package draft03

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"filippo.io/edwards25519"
)

func TestVRFBasicOperation(t *testing.T) {
	// Generate a random seed
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatal(err)
	}

	// Generate key pair
	pk, sk := keygen(seed)

	// Test message
	message := []byte("hello world")

	// Generate proof
	proof, err := sk.Prove(message)
	if err != nil {
		t.Fatalf("Failed to generate proof: %v", err)
	}

	// Verify proof
	output1, err := pk.Verify(proof, message)
	if err != nil {
		t.Fatalf("Failed to verify proof: %v", err)
	}

	outputPkg, err := Verify(pk, message, proof)
	if err != nil {
		t.Fatalf("Failed to verify proof with package-level helper: %v", err)
	}
	if !bytes.Equal(output1[:], outputPkg[:]) {
		t.Fatal("Method and package-level verification returned different outputs")
	}

	// Verify again to ensure deterministic output
	output2, err := pk.Verify(proof, message)
	if err != nil {
		t.Fatalf("Failed to verify proof second time: %v", err)
	}

	// Outputs should be identical
	if !bytes.Equal(output1[:], output2[:]) {
		t.Error("VRF outputs are not deterministic")
	}

	// Wrong message should fail verification
	wrongMessage := []byte("wrong message")
	_, err = pk.Verify(proof, wrongMessage)
	if err == nil {
		t.Error("Expected verification to fail for wrong message")
	}
	_, err = Verify(pk, wrongMessage, proof)
	if err == nil {
		t.Error("Expected package-level verification to fail for wrong message")
	}
}

func TestVRFDeterministic(t *testing.T) {
	seed := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

	// Generate same key pair twice
	pk1, sk1 := keygen(seed)
	pk2, sk2 := keygen(seed)

	// Keys should be identical
	if !bytes.Equal(pk1[:], pk2[:]) {
		t.Error("Public keys are not deterministic")
	}
	if !bytes.Equal(sk1[:], sk2[:]) {
		t.Error("Private keys are not deterministic")
	}

	message := []byte("test message")

	// Generate proofs
	proof1, err := sk1.Prove(message)
	if err != nil {
		t.Fatal(err)
	}
	proof2, err := sk2.Prove(message)
	if err != nil {
		t.Fatal(err)
	}

	// Proofs should be identical
	if !bytes.Equal(proof1[:], proof2[:]) {
		t.Error("Proofs are not deterministic")
	}

	// Outputs should be identical
	output1, err := pk1.Verify(proof1, message)
	if err != nil {
		t.Fatal(err)
	}
	output2, err := pk2.Verify(proof2, message)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(output1[:], output2[:]) {
		t.Error("VRF outputs are not deterministic")
	}
}

func TestKeyConstructorsAndMethods(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, SeedSize)
	wantPub, wantPriv := keygen([SeedSize]byte{
		0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
		0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
		0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
		0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
	})

	priv := NewKeyFromSeed(seed)
	if !priv.Equal(wantPriv) {
		t.Fatal("NewKeyFromSeed returned unexpected private key")
	}
	pub, ok := priv.Public().(PublicKey)
	if !ok {
		t.Fatalf("PrivateKey.Public returned %T, want PublicKey", priv.Public())
	}
	if !pub.Equal(wantPub) {
		t.Fatal("PrivateKey.Public returned unexpected public key")
	}

	gotSeed := priv.Seed()
	if !bytes.Equal(gotSeed, seed) {
		t.Fatal("PrivateKey.Seed returned unexpected seed")
	}
	gotSeed[0] ^= 0xff
	if bytes.Equal(priv.Seed(), gotSeed) {
		t.Fatal("PrivateKey.Seed returned aliased storage")
	}

	if !wantPub.Equal(crypto.PublicKey(pub)) {
		t.Fatal("PublicKey.Equal rejected equal key")
	}
	if !wantPriv.Equal(crypto.PrivateKey(priv)) {
		t.Fatal("PrivateKey.Equal rejected equal key")
	}
}

func TestGenerateKey(t *testing.T) {
	seed := bytes.Repeat([]byte{0x7f}, SeedSize)
	pub, priv, err := GenerateKey(bytes.NewReader(seed))
	if err != nil {
		t.Fatal(err)
	}
	wantPub, wantPriv := keygen([SeedSize]byte{
		0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
		0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
		0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
		0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	})
	if !pub.Equal(wantPub) || !priv.Equal(wantPriv) {
		t.Fatal("GenerateKey returned unexpected key")
	}

	_, _, err = GenerateKey(bytes.NewReader(seed[:SeedSize-1]))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("GenerateKey short reader error = %v, want %v", err, io.ErrUnexpectedEOF)
	}
}

func TestVRFInvalidInputs(t *testing.T) {
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatal(err)
	}
	pk, sk := keygen(seed)
	message := []byte("test")

	// Valid proof first
	validProof, err := sk.Prove(message)
	if err != nil {
		t.Fatal(err)
	}

	// A proof whose Gamma does not decode to a curve point is rejected before
	// any verification arithmetic runs. Corrupting an arbitrary byte of Gamma
	// only lands here about half the time, depending on the key material, so
	// use a fixed encoding that never decodes.
	badGamma := validProof
	gamma, err := hex.DecodeString("efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
	if err != nil {
		t.Fatal(err)
	}
	copy(badGamma[:32], gamma)

	_, err = pk.Verify(badGamma, message)
	if !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("Verify(undecodable Gamma) error = %v, want %v", err, ErrInvalidProof)
	}

	// A proof that decodes but carries a corrupted s fails verification.
	badS := validProof
	badS[ProofSize-1] ^= 1

	_, err = pk.Verify(badS, message)
	if !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("Verify(corrupted s) error = %v, want %v", err, ErrVerifyFailed)
	}

	var zero PrivateKey
	if _, err := zero.Prove(message); !errors.Is(err, ErrSmallOrderPoint) {
		t.Fatalf("zero private key error = %v, want %v", err, ErrSmallOrderPoint)
	}
}

func FuzzVerify(f *testing.F) {
	for _, v := range algorandParityVectors {
		publicKey, err := hex.DecodeString(v.publicKey)
		if err != nil {
			f.Fatal(err)
		}
		proof, err := hex.DecodeString(v.proof)
		if err != nil {
			f.Fatal(err)
		}
		message, err := hex.DecodeString(v.message)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(publicKey, proof, message)
	}
	f.Fuzz(func(t *testing.T, publicKey, proof, message []byte) {
		pk, err := ParsePublicKey(publicKey)
		if err != nil {
			return
		}
		pi, err := ParseProof(proof)
		if err != nil {
			return
		}
		Verify(pk, message, pi)
	})
}

func TestParseAndErrorSentinels(t *testing.T) {
	var seed [SeedSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatal(err)
	}
	pk, sk := keygen(seed)
	message := []byte("test")

	proof, err := sk.Prove(message)
	if err != nil {
		t.Fatal(err)
	}

	parsedPK, err := ParsePublicKey(pk[:])
	if err != nil {
		t.Fatal(err)
	}
	if !parsedPK.Equal(pk) {
		t.Fatal("ParsePublicKey did not round-trip")
	}
	parsedProof, err := ParseProof(proof[:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsedProof[:], proof[:]) {
		t.Fatal("ParseProof did not round-trip")
	}
	if _, err := parsedPK.Verify(parsedProof, message); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		fn   func() error
		want error
	}{
		{
			name: "short public key",
			fn: func() error {
				_, err := ParsePublicKey(pk[:PublicKeySize-1])
				return err
			},
			want: ErrInvalidPublicKey,
		},
		{
			name: "short proof",
			fn: func() error {
				_, err := ParseProof(proof[:ProofSize-1])
				return err
			},
			want: ErrInvalidProof,
		},
		{
			name: "wrong message",
			fn: func() error {
				_, err := pk.Verify(proof, []byte("wrong message"))
				return err
			},
			want: ErrVerifyFailed,
		},
		{
			name: "small order public key",
			fn: func() error {
				var small PublicKey
				copy(small[:], edwards25519.NewIdentityPoint().Bytes())
				_, err := small.Verify(proof, message)
				return err
			},
			want: ErrSmallOrderPoint,
		},
		{
			name: "invalid public key point",
			fn: func() error {
				var invalid PublicKey
				b, err := hex.DecodeString("efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
				if err != nil {
					return err
				}
				copy(invalid[:], b)
				_, err = invalid.Verify(proof, message)
				return err
			},
			want: ErrInvalidPublicKey,
		},
		{
			name: "truncated proof",
			fn: func() error {
				var Gamma edwards25519.Point
				_, _, err := decodeProof(&Gamma, proof[:ProofSize-1])
				return err
			},
			want: ErrInvalidProof,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.fn(); !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestOutputPrefixUint64(t *testing.T) {
	var out Output
	copy(out[:8], []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef})

	got := out.PrefixUint64()
	want := binary.BigEndian.Uint64(out[:8])
	if got != want {
		t.Fatalf("PrefixUint64 = %#x, want %#x", got, want)
	}
}

// TestProofToHashValidates checks that the standalone proofToHash still
// decodes and validates a proof itself, independently of vrfVerify.
func TestProofToHashValidates(t *testing.T) {
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatal(err)
	}
	_, sk := keygen(seed)
	message := []byte("proof to hash validation")
	proof, err := sk.Prove(message)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		proof []byte
	}{
		{"truncated", proof[:ProofSize-1]},
		{"empty", nil},
		{"oversized", append(append([]byte(nil), proof[:]...), 0)},
		{"non-canonical Gamma", func() []byte {
			bad := append([]byte(nil), proof[:]...)
			gamma, err := hex.DecodeString("efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
			if err != nil {
				t.Fatal(err)
			}
			copy(bad[:32], gamma)
			return bad
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := proofToHash(tt.proof); !errors.Is(err, ErrInvalidProof) {
				t.Fatalf("proofToHash error = %v, want %v", err, ErrInvalidProof)
			}
		})
	}

	// A well-formed proof still hashes.
	if _, err := proofToHash(proof[:]); err != nil {
		t.Fatalf("proofToHash(valid) = %v, want nil", err)
	}
}

// TestVerifyReusesValidatedGamma checks that Verify, which hashes the Gamma
// left behind by vrfVerify rather than decoding the proof a second time,
// produces the same output as the standalone decode-and-hash path.
func TestVerifyReusesValidatedGamma(t *testing.T) {
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatal(err)
	}
	pk, sk := keygen(seed)

	for _, size := range []int{0, 1, 64, 1024} {
		message := make([]byte, size)
		for i := range message {
			message[i] = byte(i*31 + 7)
		}
		proof, err := sk.Prove(message)
		if err != nil {
			t.Fatal(err)
		}

		got, err := pk.Verify(proof, message)
		if err != nil {
			t.Fatalf("Verify(%d-byte message) = %v", size, err)
		}
		want, err := proofToHash(proof[:])
		if err != nil {
			t.Fatalf("proofToHash(%d-byte message) = %v", size, err)
		}
		if got != want {
			t.Fatalf("message size %d: Verify output = %x, proofToHash = %x", size, got, want)
		}
	}
}

// TestVerifyRejectsBeforeHashing checks that a proof failing verification
// returns ErrVerifyFailed and no output, so the reused Gamma is never hashed
// for a proof that did not verify.
func TestVerifyRejectsBeforeHashing(t *testing.T) {
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatal(err)
	}
	pk, sk := keygen(seed)
	message := []byte("reject before hashing")
	proof, err := sk.Prove(message)
	if err != nil {
		t.Fatal(err)
	}

	// Flip a bit in s so the challenge no longer matches.
	tampered := proof
	tampered[ProofSize-1] ^= 1

	out, err := pk.Verify(tampered, message)
	if !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("Verify(tampered) error = %v, want %v", err, ErrVerifyFailed)
	}
	if out != (Output{}) {
		t.Fatalf("Verify(tampered) output = %x, want zero", out)
	}

	// Verifying against the wrong message must also fail without an output.
	out, err = pk.Verify(proof, []byte("different message"))
	if !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("Verify(wrong message) error = %v, want %v", err, ErrVerifyFailed)
	}
	if out != (Output{}) {
		t.Fatalf("Verify(wrong message) output = %x, want zero", out)
	}
}

func BenchmarkVRFProve(b *testing.B) {
	seed, message := benchmarkVRFFixture(0)
	_, sk := keygen(seed)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proof, err := sk.Prove(message)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkProof = proof
	}
}

func BenchmarkVRFVerify(b *testing.B) {
	seed, message := benchmarkVRFFixture(0)
	pk, sk := keygen(seed)

	proof, err := sk.Prove(message)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		output, err := pk.Verify(proof, message)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkOutput = output
	}
}

var (
	benchmarkProof  Proof
	benchmarkOutput Output
)

func benchmarkVRFFixture(index int) ([SeedSize]byte, []byte) {
	var seed [SeedSize]byte
	for i := range seed {
		seed[i] = byte(index + i*31)
	}

	message := make([]byte, 100)
	for i := range message {
		message[i] = byte(index*17 + i*29)
	}
	return seed, message
}
