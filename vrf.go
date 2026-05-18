package vrf

import (
	"crypto"
	cryptorand "crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
)

const (
	// PublicKeySize is the size of a VRF public key in bytes
	PublicKeySize = 32
	// PrivateKeySize is the size of a VRF private key in bytes
	PrivateKeySize = 64
	// SeedSize is the size of a VRF private key seed in bytes
	SeedSize = 32
	// ProofSize is the size of a VRF proof in bytes
	ProofSize = 80
	// OutputSize is the size of VRF output in bytes
	OutputSize = 64

	// vrfSuite identifies ECVRF-EDWARDS25519-SHA512-ELL2 ciphersuite
	vrfSuite = 0x04

	// SuiteString identifies the draft-03 suite implemented by this package.
	SuiteString = "ECVRF-ED25519-SHA512-Elligator2 (draft-03)"
)

// PublicKey represents a VRF public key
type PublicKey [PublicKeySize]byte

// PrivateKey represents a VRF private key (32-byte seed + 32-byte public key)
type PrivateKey [PrivateKeySize]byte

// Proof represents a VRF proof
type Proof [ProofSize]byte

// Output represents VRF output hash
type Output [OutputSize]byte

var (
	// ErrInvalidPublicKey reports a malformed public key.
	ErrInvalidPublicKey = errors.New("vrf: invalid public key")

	// ErrSmallOrderPoint reports a public key with small order.
	ErrSmallOrderPoint = errors.New("vrf: public key is a small-order point")

	// ErrInvalidProof reports a malformed or invalid VRF proof.
	ErrInvalidProof = errors.New("vrf: invalid proof")

	// ErrVerifyFailed reports a proof that does not verify.
	ErrVerifyFailed = errors.New("vrf: proof verification failed")
)

// PrefixUint64 returns the first 8 bytes of o interpreted as a big-endian
// unsigned integer.
//
// The result is a lossy prefix of the 64-byte VRF output, intended for
// sortition-style threshold comparisons. Use o directly when the full VRF
// output is required.
func (o Output) PrefixUint64() uint64 {
	return binary.BigEndian.Uint64(o[:8])
}

// GenerateKey generates a new VRF key pair using rand.
//
// If rand is nil, crypto/rand.Reader is used.
func GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error) {
	if rand == nil {
		rand = cryptorand.Reader
	}
	var seed [SeedSize]byte
	if _, err := io.ReadFull(rand, seed[:]); err != nil {
		return PublicKey{}, PrivateKey{}, fmt.Errorf("read seed: %w", err)
	}
	pub, priv := keygen(seed)
	return pub, priv, nil
}

// ParsePublicKey returns a PublicKey from its 32-byte encoding.
//
// It validates the length only. Point decoding and small-order checks happen
// during verification.
func ParsePublicKey(b []byte) (PublicKey, error) {
	var pk PublicKey
	if len(b) != PublicKeySize {
		return pk, fmt.Errorf("%w: must be %d bytes, got %d", ErrInvalidPublicKey, PublicKeySize, len(b))
	}
	copy(pk[:], b)
	return pk, nil
}

// ParseProof returns a Proof from its 80-byte encoding.
func ParseProof(b []byte) (Proof, error) {
	var proof Proof
	if len(b) != ProofSize {
		return proof, fmt.Errorf("%w: must be %d bytes, got %d", ErrInvalidProof, ProofSize, len(b))
	}
	copy(proof[:], b)
	return proof, nil
}

// NewKeyFromSeed derives a VRF private key from seed.
//
// It panics if len(seed) is not SeedSize, matching crypto/ed25519.NewKeyFromSeed.
func NewKeyFromSeed(seed []byte) PrivateKey {
	if len(seed) != SeedSize {
		panic("vrf: bad seed length")
	}
	var fixed [SeedSize]byte
	copy(fixed[:], seed)
	_, priv := keygen(fixed)
	return priv
}

func keygen(seed [SeedSize]byte) (PublicKey, PrivateKey) {
	var pk PublicKey
	var sk PrivateKey

	h := sha512.New()
	h.Write(seed[:])
	hSum := h.Sum(nil)

	p := edwards25519.NewScalar()
	p.SetBytesWithClamping(hSum[:32])

	A := edwards25519.NewIdentityPoint().ScalarBaseMult(p)
	copy(pk[:], A.Bytes())
	copy(sk[:], seed[:])
	copy(sk[32:], pk[:])

	return pk, sk
}

// Public returns the public key corresponding to sk.
func (sk PrivateKey) Public() crypto.PublicKey {
	var pk PublicKey
	copy(pk[:], sk[SeedSize:])
	return pk
}

// Seed returns a copy of sk's private key seed.
func (sk PrivateKey) Seed() []byte {
	seed := make([]byte, SeedSize)
	copy(seed, sk[:SeedSize])
	return seed
}

// Equal reports whether sk and x contain the same private key.
func (sk PrivateKey) Equal(x crypto.PrivateKey) bool {
	other, ok := x.(PrivateKey)
	return ok && subtle.ConstantTimeCompare(sk[:], other[:]) == 1
}

// Equal reports whether pk and x contain the same public key.
func (pk PublicKey) Equal(x crypto.PublicKey) bool {
	other, ok := x.(PublicKey)
	return ok && subtle.ConstantTimeCompare(pk[:], other[:]) == 1
}

// Verify is the package-level form of (PublicKey).Verify, with arguments in
// ed25519.Verify order: pub, msg, proof.
//
// The method form keeps the historical order, proof before message.
func Verify(pub PublicKey, msg []byte, proof Proof) (Output, error) {
	return pub.Verify(proof, msg)
}

// Prove generates a VRF proof for the given message
func (sk PrivateKey) Prove(message []byte) (Proof, error) {
	Y, xScalar, truncHashedSk, err := sk.expand()
	if err != nil {
		return Proof{}, err
	}

	return vrfProve(Y, xScalar, truncHashedSk, message)
}

// Verify verifies a VRF proof and returns the VRF output if valid
func (pk PublicKey) Verify(proof Proof, message []byte) (Output, error) {
	var out Output

	hash, err := vrfVerifyAndHash(pk[:], proof[:], message)
	if err != nil {
		return out, err
	}

	copy(out[:], hash)
	return out, nil
}

// expand converts a private key into the public point Y, private scalar x,
// and truncated hash for nonce generation
func (sk PrivateKey) expand() (*edwards25519.Point, *edwards25519.Scalar, []byte, error) {
	h := sha512.New()
	h.Write(sk[:32])
	hSum := h.Sum(nil)

	xScalar := edwards25519.NewScalar()
	xScalar.SetBytesWithClamping(hSum[:32])

	truncHashedSk := hSum[32:]

	Y := edwards25519.NewIdentityPoint()
	if _, err := Y.SetBytes(sk[32:]); err != nil {
		return nil, nil, nil, fmt.Errorf("%w: private key public half: %v", ErrInvalidPublicKey, err)
	}

	return Y, xScalar, truncHashedSk, nil
}

// vrfVerifyAndHash verifies a VRF proof and returns the output hash
func vrfVerifyAndHash(pk []byte, proof []byte, message []byte) ([]byte, error) {
	Y := &edwards25519.Point{}
	if _, err := Y.SetBytes(pk); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
	}

	// Check if public key has small order
	isSmallOrder := (&edwards25519.Point{}).MultByCofactor(Y).Equal(edwards25519.NewIdentityPoint()) == 1
	if isSmallOrder {
		return nil, ErrSmallOrderPoint
	}

	// Verify the proof
	ok, err := vrfVerify(Y, proof, message)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrVerifyFailed
	}

	// Convert proof to hash
	return proofToHash(proof)
}

// vrfProve constructs a VRF proof for a message
func vrfProve(Y *edwards25519.Point, xScalar *edwards25519.Scalar, truncHashedSk []byte, message []byte) (Proof, error) {
	var proof Proof

	// Hash message to curve point
	H, err := hashToCurve(Y, message)
	if err != nil {
		return Proof{}, err
	}

	// Gamma = x * H
	Gamma := new(edwards25519.Point).ScalarMult(xScalar, H)

	// Generate nonce
	k := nonceGeneration(truncHashedSk, H)

	// kB = k * B (base point)
	kB := edwards25519.NewIdentityPoint().ScalarBaseMult(k)

	// kH = k * H
	kH := edwards25519.NewIdentityPoint().ScalarMult(k, H)

	// c = hash_points(H, Gamma, kB, kH)
	c := hashPoints(H, Gamma, kB, kH)

	// s = c*x + k (mod q)
	s := edwards25519.NewScalar()
	s.MultiplyAdd(c, xScalar, k)

	// Encode proof as Gamma || c (16 bytes) || s
	copy(proof[:], Gamma.Bytes())
	copy(proof[32:], c.Bytes()[:16])
	copy(proof[48:], s.Bytes())

	return proof, nil
}

// hashToCurve hashes a message to a curve point using Elligator2
func hashToCurve(Y *edwards25519.Point, message []byte) (*edwards25519.Point, error) {
	h := sha512.New()
	h.Write([]byte{vrfSuite})
	h.Write([]byte{1})
	h.Write(Y.Bytes())
	h.Write(message)

	rString := h.Sum(nil)
	rString[31] &= 0x7f // clear sign bit

	hBytes, err := elligator2(rString)
	if err != nil {
		return nil, err
	}

	result := &edwards25519.Point{}
	if _, err := result.SetBytes(hBytes); err != nil {
		return nil, err
	}

	return result, nil
}

// elligator2 implements the Elligator2 map from uniform bytes to Edwards25519 point
func elligator2(r []byte) ([]byte, error) {
	s := make([]byte, 32)
	copy(s, r[:32])

	xSign := s[31] & 0x80
	s[31] &= 0x7f

	one := new(field.Element).One()

	// rr2 = 2*r^2
	rr2 := &field.Element{}
	rr2.SetBytes(s)
	rr2.Square(rr2)
	rr2.Add(rr2, rr2)
	rr2.Add(rr2, one)
	rr2.Invert(rr2)

	// x = -A * rr2
	const curve25519A = 486662
	curve25519AElement := new(field.Element).Mult32(one, curve25519A)

	x := &field.Element{}
	x.Mult32(rr2, curve25519A)
	x.Negate(x)

	// Compute x^2 and x^3
	x2 := &field.Element{}
	x2.Multiply(x, x)
	x3 := &field.Element{}
	x3.Multiply(x, x2)

	// e = x^3 + A*x^2 + x
	e := &field.Element{}
	e.Add(x3, x)
	x2.Mult32(x2, curve25519A)
	e.Add(x2, e)

	// Check if e is a quadratic residue
	e = chi25519(e)
	eBytes := e.Bytes()

	eIsMinus1 := int(eBytes[1] & 1)
	eIsNotMinus1 := eIsMinus1 ^ 1

	negx := new(field.Element).Negate(x)
	x.Select(x, negx, eIsNotMinus1)

	x2.Zero()
	x2.Select(x2, curve25519AElement, eIsNotMinus1)
	x.Subtract(x, x2)

	// Convert to Edwards coordinates: yed = (x-1)/(x+1)
	xPlusOne := new(field.Element).Add(x, one)
	xMinusOne := new(field.Element).Subtract(x, one)
	xPlusOneInv := new(field.Element).Invert(xPlusOne)
	yed := new(field.Element).Multiply(xMinusOne, xPlusOneInv)

	s = yed.Bytes()
	s[31] |= xSign

	// Decode as Edwards point and multiply by cofactor
	p3 := &edwards25519.Point{}
	if _, err := p3.SetBytes(s); err != nil {
		return nil, err
	}

	p3.MultByCofactor(p3)
	return p3.Bytes(), nil
}

// nonceGeneration generates a deterministic nonce for VRF proving
func nonceGeneration(truncHashedSk []byte, H *edwards25519.Point) *edwards25519.Scalar {
	h := sha512.New()
	h.Write(truncHashedSk)
	h.Write(H.Bytes())

	kBytes := h.Sum(nil)
	k := edwards25519.NewScalar()
	k.SetUniformBytes(kBytes)

	return k
}

// hashPoints hashes four points to produce a scalar challenge
func hashPoints(P1, P2, P3, P4 *edwards25519.Point) *edwards25519.Scalar {
	var input [2 + 32*4]byte

	input[0] = vrfSuite
	input[1] = 0x02
	copy(input[2:], P1.Bytes())
	copy(input[34:], P2.Bytes())
	copy(input[66:], P3.Bytes())
	copy(input[98:], P4.Bytes())

	h := sha512.New()
	h.Write(input[:])
	sum := h.Sum(nil)

	// Use first 16 bytes as 32-byte scalar (zero-padded)
	result := make([]byte, 32)
	copy(result, sum[:16])

	scalar := edwards25519.NewScalar()
	if _, err := scalar.SetCanonicalBytes(result); err != nil {
		panic("invalid scalar from hash")
	}

	return scalar
}

// chi25519 computes the Legendre symbol for field elements (quadratic residue test)
func chi25519(z *field.Element) *field.Element {
	out := &field.Element{}
	out.Set(z)

	var t0, t1, t2, t3 *field.Element

	t0 = &field.Element{}
	t1 = &field.Element{}
	t2 = &field.Element{}
	t3 = &field.Element{}

	t0.Square(z)
	t1.Multiply(t0, z)
	t0.Square(t1)
	t2.Square(t0)
	t2.Square(t2)
	t2.Multiply(t2, t0)
	t1.Multiply(t2, z)
	t2.Square(t1)

	for i := 1; i < 5; i++ {
		t2.Square(t2)
	}
	t1.Multiply(t2, t1)
	t2.Square(t1)

	for i := 1; i < 10; i++ {
		t2.Square(t2)
	}
	t2.Multiply(t2, t1)
	t3.Square(t2)

	for i := 1; i < 20; i++ {
		t3.Square(t3)
	}
	t2.Multiply(t3, t2)
	t2.Square(t2)

	for i := 1; i < 10; i++ {
		t2.Square(t2)
	}
	t1.Multiply(t2, t1)
	t2.Square(t1)

	for i := 1; i < 50; i++ {
		t2.Square(t2)
	}
	t2.Multiply(t2, t1)
	t3.Square(t2)

	for i := 1; i < 100; i++ {
		t3.Square(t3)
	}
	t2.Multiply(t3, t2)
	t2.Square(t2)

	for i := 1; i < 50; i++ {
		t2.Square(t2)
	}
	t1.Multiply(t2, t1)
	t1.Square(t1)

	for i := 1; i < 4; i++ {
		t1.Square(t1)
	}
	out.Multiply(t1, t0)

	return out
}

// vrfVerify verifies a VRF proof
func vrfVerify(Y *edwards25519.Point, pi []byte, message []byte) (bool, error) {
	// Decode proof
	Gamma, cBytes, sBytes, err := decodeProof(pi)
	if err != nil {
		return false, err
	}

	// Hash message to curve
	H, err := hashToCurve(Y, message)
	if err != nil {
		return false, err
	}

	// Reconstruct scalars c and s
	cBytes64 := make([]byte, 64)
	copy(cBytes64, cBytes)
	c := edwards25519.NewScalar()
	c.SetUniformBytes(cBytes64)

	sBytes64 := make([]byte, 64)
	copy(sBytes64, sBytes)
	s := edwards25519.NewScalar()
	s.SetUniformBytes(sBytes64)

	// U = s*B - c*Y
	cY := new(edwards25519.Point).ScalarMult(c, Y)
	sB := new(edwards25519.Point).ScalarBaseMult(s)
	U := new(edwards25519.Point).Subtract(sB, cY)

	// V = s*H - c*Gamma
	sH := new(edwards25519.Point).ScalarMult(s, H)
	cGamma := new(edwards25519.Point).ScalarMult(c, Gamma)
	V := new(edwards25519.Point).Subtract(sH, cGamma)

	// cprime = hash_points(H, Gamma, U, V)
	cprime := hashPoints(H, Gamma, U, V)

	// Verify c == cprime (first 16 bytes)
	return subtle.ConstantTimeCompare(cBytes, cprime.Bytes()[:16]) == 1, nil
}

// proofToHash converts a VRF proof to its output hash
func proofToHash(pi []byte) ([]byte, error) {
	Gamma, _, _, err := decodeProof(pi)
	if err != nil {
		return nil, err
	}

	var hashInput [34]byte
	hashInput[0] = vrfSuite
	hashInput[1] = 0x03

	// Apply cofactor to Gamma
	Gamma.MultByCofactor(Gamma)
	copy(hashInput[2:], Gamma.Bytes())

	h := sha512.New()
	h.Write(hashInput[:])
	return h.Sum(nil), nil
}

// decodeProof decodes an 80-byte VRF proof
func decodeProof(pi []byte) (*edwards25519.Point, []byte, []byte, error) {
	if len(pi) != ProofSize {
		return nil, nil, nil, fmt.Errorf("%w: proof must be %d bytes, got %d", ErrInvalidProof, ProofSize, len(pi))
	}

	// Gamma = pi[0:32]
	Gamma := &edwards25519.Point{}
	if _, err := Gamma.SetBytes(pi[:32]); err != nil {
		return nil, nil, nil, fmt.Errorf("%w: invalid Gamma point: %v", ErrInvalidProof, err)
	}

	// c = pi[32:48] (16 bytes)
	c := make([]byte, 16)
	copy(c, pi[32:48])

	// s = pi[48:80] (32 bytes)
	s := make([]byte, 32)
	copy(s, pi[48:80])

	return Gamma, c, s, nil
}
