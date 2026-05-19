package vrf

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

	// Test invalid proof size
	invalidProof := Proof{}
	copy(invalidProof[:], validProof[:])
	invalidProof[0] ^= 1 // Corrupt first byte

	_, err = pk.Verify(invalidProof, message)
	if !errors.Is(err, ErrInvalidProof) && !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("corrupted proof error = %v, want ErrInvalidProof or ErrVerifyFailed", err)
	}
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
				_, _, _, err := decodeProof(proof[:ProofSize-1])
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

func BenchmarkVRFProve(b *testing.B) {
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		b.Fatal(err)
	}
	_, sk := keygen(seed)
	message := []byte("benchmark message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sk.Prove(message)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVRFVerify(b *testing.B) {
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		b.Fatal(err)
	}
	pk, sk := keygen(seed)
	message := []byte("benchmark message")

	proof, err := sk.Prove(message)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := pk.Verify(proof, message)
		if err != nil {
			b.Fatal(err)
		}
	}
}
