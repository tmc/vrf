package draft03

import (
	"io"

	vrf "github.com/tmc/vrf"
)

const (
	// PublicKeySize is the size of a VRF public key in bytes.
	PublicKeySize = vrf.PublicKeySize
	// PrivateKeySize is the size of a VRF private key in bytes.
	PrivateKeySize = vrf.PrivateKeySize
	// SeedSize is the size of a VRF private key seed in bytes.
	SeedSize = vrf.SeedSize
	// ProofSize is the size of a VRF proof in bytes.
	ProofSize = vrf.ProofSize
	// OutputSize is the size of a VRF output in bytes.
	OutputSize = vrf.OutputSize

	// SuiteString identifies the draft-03 suite.
	SuiteString = vrf.SuiteString
)

// PublicKey represents a draft-03 VRF public key.
type PublicKey = vrf.PublicKey

// PrivateKey represents a draft-03 VRF private key.
type PrivateKey = vrf.PrivateKey

// Proof represents a draft-03 VRF proof.
type Proof = vrf.Proof

// Output represents a draft-03 VRF output hash.
type Output = vrf.Output

var (
	// ErrInvalidPublicKey reports a malformed public key.
	ErrInvalidPublicKey = vrf.ErrInvalidPublicKey

	// ErrSmallOrderPoint reports a public key with small order.
	ErrSmallOrderPoint = vrf.ErrSmallOrderPoint

	// ErrInvalidProof reports a malformed or invalid VRF proof.
	ErrInvalidProof = vrf.ErrInvalidProof

	// ErrVerifyFailed reports a proof that does not verify.
	ErrVerifyFailed = vrf.ErrVerifyFailed
)

// GenerateKey generates a new draft-03 VRF key pair using rand.
//
// If rand is nil, crypto/rand.Reader is used.
func GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error) {
	return vrf.GenerateKey(rand)
}

// ParsePublicKey returns a PublicKey from its 32-byte encoding.
func ParsePublicKey(b []byte) (PublicKey, error) {
	return vrf.ParsePublicKey(b)
}

// ParseProof returns a Proof from its 80-byte encoding.
func ParseProof(b []byte) (Proof, error) {
	return vrf.ParseProof(b)
}

// NewKeyFromSeed derives a VRF private key from seed.
//
// It panics if len(seed) is not SeedSize, matching crypto/ed25519.NewKeyFromSeed.
func NewKeyFromSeed(seed []byte) PrivateKey {
	return vrf.NewKeyFromSeed(seed)
}

// Verify is the package-level form of (PublicKey).Verify, with arguments in
// ed25519.Verify order: pub, msg, proof.
//
// The method form keeps proof before message because the receiver supplies the
// public key.
func Verify(pub PublicKey, msg []byte, proof Proof) (Output, error) {
	return vrf.Verify(pub, msg, proof)
}
