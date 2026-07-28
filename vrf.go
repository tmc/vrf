package vrf

import (
	"io"

	"github.com/tmc/vrf/rfc9381"
)

const (
	// PublicKeySize is the size of a VRF public key in bytes.
	PublicKeySize = rfc9381.PublicKeySize
	// PrivateKeySize is the size of a VRF private key in bytes.
	PrivateKeySize = rfc9381.PrivateKeySize
	// SeedSize is the size of a VRF private key seed in bytes.
	SeedSize = rfc9381.SeedSize
	// ProofSize is the size of a VRF proof in bytes.
	ProofSize = rfc9381.ProofSize
	// OutputSize is the size of a VRF output in bytes.
	OutputSize = rfc9381.OutputSize

	// SuiteString identifies the RFC 9381 suite.
	SuiteString = rfc9381.SuiteString
)

// PublicKey represents an RFC 9381 VRF public key.
type PublicKey = rfc9381.PublicKey

// PrivateKey represents an RFC 9381 VRF private key.
type PrivateKey = rfc9381.PrivateKey

// Proof represents an RFC 9381 VRF proof.
type Proof = rfc9381.Proof

// Output represents an RFC 9381 VRF output hash.
type Output = rfc9381.Output

var (
	// ErrInvalidPublicKey reports a malformed public key.
	ErrInvalidPublicKey = rfc9381.ErrInvalidPublicKey

	// ErrSmallOrderPoint reports a public key with small order. It wraps
	// ErrInvalidPublicKey, since such a key is a species of invalid key.
	ErrSmallOrderPoint = rfc9381.ErrSmallOrderPoint

	// ErrInvalidProof reports a malformed or invalid VRF proof.
	ErrInvalidProof = rfc9381.ErrInvalidProof

	// ErrVerifyFailed reports a proof that does not verify.
	ErrVerifyFailed = rfc9381.ErrVerifyFailed
)

// GenerateKey generates a new VRF key pair using rand.
//
// If rand is nil, crypto/rand.Reader is used.
func GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error) {
	return rfc9381.GenerateKey(rand)
}

// ParsePublicKey returns a PublicKey from its 32-byte encoding.
//
// It rejects encodings that do not decode to a curve point, and points of small
// order.
func ParsePublicKey(b []byte) (PublicKey, error) {
	return rfc9381.ParsePublicKey(b)
}

// ParseProof returns a Proof from its 80-byte encoding.
func ParseProof(b []byte) (Proof, error) {
	return rfc9381.ParseProof(b)
}

// NewKeyFromSeed derives a VRF private key from seed.
//
// It panics if len(seed) is not SeedSize, matching crypto/ed25519.NewKeyFromSeed.
func NewKeyFromSeed(seed []byte) PrivateKey {
	return rfc9381.NewKeyFromSeed(seed)
}

// Verify is the package-level form of (PublicKey).Verify, with arguments in
// ed25519.Verify order: pub, msg, proof.
//
// The method form keeps proof before message because the receiver supplies the
// public key.
func Verify(pub PublicKey, msg []byte, proof Proof) (Output, error) {
	return rfc9381.Verify(pub, msg, proof)
}
