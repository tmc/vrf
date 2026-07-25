package draft03

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
	// PublicKeySize is the size of a VRF public key in bytes.
	PublicKeySize = 32
	// PrivateKeySize is the size of a VRF private key in bytes.
	PrivateKeySize = 64
	// SeedSize is the size of a VRF private key seed in bytes.
	SeedSize = 32
	// ProofSize is the size of a VRF proof in bytes.
	ProofSize = 80
	// OutputSize is the size of VRF output in bytes.
	OutputSize = 64

	// vrfSuite identifies ECVRF-EDWARDS25519-SHA512-ELL2 ciphersuite
	vrfSuite = 0x04

	// SuiteString identifies the draft-03 suite implemented by this package.
	SuiteString = "ECVRF-ED25519-SHA512-Elligator2 (draft-03)"
)

// PublicKey represents a VRF public key.
//
// The zero value is not a usable key. Obtain one from GenerateKey,
// ParsePublicKey, or (PrivateKey).Public.
type PublicKey [PublicKeySize]byte

// PrivateKey represents a VRF private key (32-byte seed + 32-byte public key).
//
// The zero value is not a usable key: its public half decodes to the identity
// point, so Prove reports ErrSmallOrderPoint. Obtain one from GenerateKey or
// NewKeyFromSeed.
type PrivateKey [PrivateKeySize]byte

// Proof represents a VRF proof.
type Proof [ProofSize]byte

// Output represents a VRF output hash.
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

	identityPoint = edwards25519.NewIdentityPoint()
	oneFE         = new(field.Element).One()
	curve25519AFE = new(field.Element).Mult32(oneFE, curve25519A)
)

const curve25519A = 486662

// PrefixUint64 returns the first 8 bytes of o interpreted as a big-endian
// unsigned integer.
//
// The result is a lossy prefix of the 64-byte VRF output, intended for
// sortition-style threshold comparisons. Use o directly when the full VRF
// output is required.
func (o Output) PrefixUint64() uint64 {
	return binary.BigEndian.Uint64(o[:8])
}

// GenerateKey generates a new VRF key pair using random.
//
// If random is nil, crypto/rand.Reader is used.
func GenerateKey(random io.Reader) (PublicKey, PrivateKey, error) {
	if random == nil {
		random = cryptorand.Reader
	}
	var seed [SeedSize]byte
	if _, err := io.ReadFull(random, seed[:]); err != nil {
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

	hSum := sha512.Sum512(seed[:])

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
// The method form keeps proof before message because the receiver supplies the
// public key.
func Verify(pub PublicKey, msg []byte, proof Proof) (Output, error) {
	return pub.Verify(proof, msg)
}

// Prove generates a VRF proof for message.
func (sk PrivateKey) Prove(message []byte) (Proof, error) {
	Y := &edwards25519.Point{}
	if _, err := Y.SetBytes(sk[SeedSize:]); err != nil {
		return Proof{}, fmt.Errorf("%w: private key public half: %v", ErrInvalidPublicKey, err)
	}
	if isSmallOrder(Y) {
		return Proof{}, ErrSmallOrderPoint
	}
	var xScalar edwards25519.Scalar
	truncHashedSk := sk.expand(&xScalar)
	return vrfProve(sk[32:], &xScalar, truncHashedSk, message)
}

// Verify verifies proof over message and returns the VRF output if valid.
//
// The method argument order is proof, message. The package-level Verify uses
// pub, message, proof to match crypto/ed25519.Verify.
func (pk PublicKey) Verify(proof Proof, message []byte) (Output, error) {
	return vrfVerifyAndHash(pk[:], proof[:], message)
}

// expand converts a private key into the private scalar x and truncated hash
// for nonce generation.
func (sk PrivateKey) expand(xScalar *edwards25519.Scalar) [32]byte {
	hSum := sha512.Sum512(sk[:32])

	xScalar.SetBytesWithClamping(hSum[:32])

	var truncHashedSk [32]byte
	copy(truncHashedSk[:], hSum[32:])

	return truncHashedSk
}

// vrfVerifyAndHash verifies a VRF proof and returns the output hash
func vrfVerifyAndHash(pk []byte, proof []byte, message []byte) (Output, error) {
	Y := &edwards25519.Point{}
	if _, err := Y.SetBytes(pk); err != nil {
		return Output{}, fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
	}

	if isSmallOrder(Y) {
		return Output{}, ErrSmallOrderPoint
	}

	// vrfVerify leaves the decoded and validated Gamma in Gamma, so hashing it
	// below does not decode the proof a second time.
	var Gamma edwards25519.Point
	ok, err := vrfVerify(&Gamma, pk, Y, proof, message)
	if err != nil {
		return Output{}, err
	}
	if !ok {
		return Output{}, ErrVerifyFailed
	}

	return proofToHashPoint(&Gamma), nil
}

func isSmallOrder(p *edwards25519.Point) bool {
	return (&edwards25519.Point{}).MultByCofactor(p).Equal(identityPoint) == 1
}

// vrfProve constructs a VRF proof for a message
func vrfProve(YBytes []byte, xScalar *edwards25519.Scalar, truncHashedSk [32]byte, message []byte) (Proof, error) {
	var proof Proof

	// Hash message to curve point
	var H edwards25519.Point
	HBytes, err := hashToCurve(&H, YBytes, message)
	if err != nil {
		return Proof{}, err
	}

	// Gamma = x * H
	Gamma := new(edwards25519.Point).ScalarMult(xScalar, &H)
	GammaBytes := pointBytes(Gamma)

	// Generate nonce
	var k edwards25519.Scalar
	nonceGeneration(&k, truncHashedSk, HBytes)

	// kB = k * B (base point)
	kB := edwards25519.NewIdentityPoint().ScalarBaseMult(&k)
	kBBytes := pointBytes(kB)

	// kH = k * H
	kH := edwards25519.NewIdentityPoint().ScalarMult(&k, &H)
	kHBytes := pointBytes(kH)

	// c = hash_points(H, Gamma, kB, kH)
	var c edwards25519.Scalar
	hashPoints(&c, HBytes, GammaBytes, kBBytes, kHBytes)

	// s = c*x + k (mod q)
	var s edwards25519.Scalar
	s.Multiply(&c, xScalar)
	s.Add(&s, &k)

	// Encode proof as Gamma || c (16 bytes) || s
	copy(proof[:], GammaBytes[:])
	copy(proof[32:], c.Bytes()[:16])
	copy(proof[48:], s.Bytes())

	return proof, nil
}

// hashToCurve hashes a message to a curve point using Elligator2
func hashToCurve(out *edwards25519.Point, YBytes []byte, message []byte) ([32]byte, error) {
	h := sha512.New()
	h.Write([]byte{vrfSuite})
	h.Write([]byte{1})
	h.Write(YBytes)
	h.Write(message)

	var rString [sha512.Size]byte
	h.Sum(rString[:0])
	rString[31] &= 0x7f // clear sign bit

	return elligator2(out, rString[:])
}

// elligator2 implements the Elligator2 map from uniform bytes to Edwards25519 point
func elligator2(p *edwards25519.Point, r []byte) ([32]byte, error) {
	var out [32]byte
	var s [32]byte
	copy(s[:], r[:32])

	xSign := s[31] & 0x80
	s[31] &= 0x7f

	// rr2 = 2*r^2
	rr2 := &field.Element{}
	rr2.SetBytes(s[:])
	rr2.Square(rr2)
	rr2.Add(rr2, rr2)
	rr2.Add(rr2, oneFE)
	rr2.Invert(rr2)

	// x = -A * rr2
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
	chi25519(e, e)
	eBytes := e.Bytes()

	eIsMinus1 := int(eBytes[1] & 1)
	eIsNotMinus1 := eIsMinus1 ^ 1

	negx := new(field.Element).Negate(x)
	x.Select(x, negx, eIsNotMinus1)

	x2.Zero()
	x2.Select(x2, curve25519AFE, eIsNotMinus1)
	x.Subtract(x, x2)

	// Convert to Edwards coordinates: yed = (x-1)/(x+1)
	xPlusOne := new(field.Element).Add(x, oneFE)
	xMinusOne := new(field.Element).Subtract(x, oneFE)
	xPlusOneInv := new(field.Element).Invert(xPlusOne)
	yed := new(field.Element).Multiply(xMinusOne, xPlusOneInv)

	copy(s[:], yed.Bytes())
	s[31] |= xSign

	// Decode as Edwards point and multiply by cofactor
	if _, err := p.SetBytes(s[:]); err != nil {
		return out, err
	}

	p.MultByCofactor(p)
	copy(out[:], p.Bytes())
	return out, nil
}

// nonceGeneration generates a deterministic nonce for VRF proving
func nonceGeneration(k *edwards25519.Scalar, truncHashedSk [32]byte, HBytes [32]byte) {
	h := sha512.New()
	h.Write(truncHashedSk[:])
	h.Write(HBytes[:])

	var kBytes [sha512.Size]byte
	h.Sum(kBytes[:0])
	k.SetUniformBytes(kBytes[:])
}

// hashPoints hashes four encoded points to produce a scalar challenge.
func hashPoints(scalar *edwards25519.Scalar, P1Bytes, P2Bytes, P3Bytes, P4Bytes [32]byte) {
	var input [2 + 32*4]byte

	input[0] = vrfSuite
	input[1] = 0x02
	copy(input[2:], P1Bytes[:])
	copy(input[34:], P2Bytes[:])
	copy(input[66:], P3Bytes[:])
	copy(input[98:], P4Bytes[:])

	sum := sha512.Sum512(input[:])

	// Use first 16 bytes as 32-byte scalar (zero-padded)
	var result [32]byte
	copy(result[:], sum[:16])

	if _, err := scalar.SetCanonicalBytes(result[:]); err != nil {
		// Unreachable: result is 16 bytes zero-padded to 32, always < the
		// group order, so it is always canonical.
		panic("vrf: invalid scalar from hash")
	}
}

// chi25519 computes the Legendre symbol for field elements (quadratic residue test)
func chi25519(out, z *field.Element) {
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
}

// vrfVerify verifies a VRF proof. On success it leaves the decoded and
// validated Gamma point in Gamma for the caller to hash.
func vrfVerify(Gamma *edwards25519.Point, YBytes []byte, Y *edwards25519.Point, pi []byte, message []byte) (bool, error) {
	// Decode proof
	cBytes, sBytes, err := decodeProof(Gamma, pi)
	if err != nil {
		return false, err
	}

	// Hash message to curve
	var H edwards25519.Point
	HBytes, err := hashToCurve(&H, YBytes, message)
	if err != nil {
		return false, err
	}

	// Reconstruct scalars c and s
	c := edwards25519.NewScalar()
	cWide := scalarBytes16(cBytes)
	if _, err := c.SetCanonicalBytes(cWide[:]); err != nil {
		return false, fmt.Errorf("%w: invalid c scalar: %v", ErrInvalidProof, err)
	}

	s := edwards25519.NewScalar()
	sWide := scalarBytes32(sBytes)
	if _, err := s.SetUniformBytes(sWide[:]); err != nil {
		return false, fmt.Errorf("%w: invalid s scalar: %v", ErrInvalidProof, err)
	}

	// U = s*B - c*Y
	cNeg := edwards25519.NewScalar().Negate(c)
	U := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(cNeg, Y, s)

	// V = s*H - c*Gamma
	scalars := [...]*edwards25519.Scalar{cNeg, s}
	points := [...]*edwards25519.Point{Gamma, &H}
	V := new(edwards25519.Point).VarTimeMultiScalarMult(scalars[:], points[:])

	// cprime = hash_points(H, Gamma, U, V)
	var GammaBytes [32]byte
	copy(GammaBytes[:], pi[:32])
	var cprime edwards25519.Scalar
	hashPoints(&cprime, HBytes, GammaBytes, pointBytes(U), pointBytes(V))

	// Verify c == cprime (first 16 bytes)
	return subtle.ConstantTimeCompare(cBytes[:], cprime.Bytes()[:16]) == 1, nil
}

// proofToHash decodes a VRF proof and converts it to its output hash. It
// validates the proof encoding independently of vrfVerify.
func proofToHash(pi []byte) (Output, error) {
	var Gamma edwards25519.Point
	if _, _, err := decodeProof(&Gamma, pi); err != nil {
		return Output{}, err
	}
	return proofToHashPoint(&Gamma), nil
}

// proofToHashPoint hashes an already decoded and validated Gamma to the VRF
// output. It modifies Gamma in place.
func proofToHashPoint(Gamma *edwards25519.Point) Output {
	var hashInput [34]byte
	hashInput[0] = vrfSuite
	hashInput[1] = 0x03

	// Apply cofactor to Gamma
	Gamma.MultByCofactor(Gamma)
	copy(hashInput[2:], Gamma.Bytes())

	return Output(sha512.Sum512(hashInput[:]))
}

// decodeProof decodes an 80-byte VRF proof, storing Gamma in the caller-owned
// point.
func decodeProof(Gamma *edwards25519.Point, pi []byte) ([16]byte, [32]byte, error) {
	var c [16]byte
	var s [32]byte
	if len(pi) != ProofSize {
		return c, s, fmt.Errorf("%w: proof must be %d bytes, got %d", ErrInvalidProof, ProofSize, len(pi))
	}

	// Gamma = pi[0:32]
	if _, err := Gamma.SetBytes(pi[:32]); err != nil {
		return c, s, fmt.Errorf("%w: invalid Gamma point: %v", ErrInvalidProof, err)
	}

	// c = pi[32:48] (16 bytes)
	copy(c[:], pi[32:48])

	// s = pi[48:80] (32 bytes)
	copy(s[:], pi[48:80])

	return c, s, nil
}

func scalarBytes16(in [16]byte) [32]byte {
	var out [32]byte
	copy(out[:], in[:])
	return out
}

func scalarBytes32(in [32]byte) [64]byte {
	var out [64]byte
	copy(out[:], in[:])
	return out
}

func pointBytes(p *edwards25519.Point) [32]byte {
	var out [32]byte
	copy(out[:], p.Bytes())
	return out
}
