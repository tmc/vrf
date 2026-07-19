package rfc9381

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
	// OutputSize is the size of a VRF output in bytes.
	OutputSize = 64

	vrfSuite = 0x04

	hashToCurveDSTString = "ECVRF_edwards25519_XMD:SHA-512_ELL2_NU_\x04"

	// SuiteString identifies the RFC 9381 suite implemented by this package.
	SuiteString = "ECVRF-EDWARDS25519-SHA512-ELL2 (RFC 9381)"
)

var (
	// ErrInvalidPublicKey reports a malformed public key.
	ErrInvalidPublicKey = errors.New("vrf: invalid public key")

	// ErrSmallOrderPoint reports a public key with small order.
	ErrSmallOrderPoint = errors.New("vrf: public key is a small-order point")

	// ErrInvalidProof reports a malformed VRF proof.
	ErrInvalidProof = errors.New("vrf: invalid proof")

	// ErrVerifyFailed reports a proof that does not verify.
	ErrVerifyFailed = errors.New("vrf: proof verification failed")
)

// PublicKey represents an RFC 9381 VRF public key.
type PublicKey [PublicKeySize]byte

// PrivateKey represents an RFC 9381 VRF private key.
type PrivateKey [PrivateKeySize]byte

// Proof represents an RFC 9381 VRF proof.
type Proof [ProofSize]byte

// Output represents an RFC 9381 VRF output hash.
type Output [OutputSize]byte

var (
	hashToCurveDST    = []byte(hashToCurveDSTString)
	oneFE             = new(field.Element).One()
	curve25519J       = new(field.Element).Mult32(oneFE, 486662)
	negCurve25519J    = new(field.Element).Negate(curve25519J)
	sqrtMinus486664FE = sqrtMinus486664()
)

// GenerateKey generates a new RFC 9381 VRF key pair using rand.
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

	h := sha512.Sum512(seed[:])
	x := edwards25519.NewScalar()
	x.SetBytesWithClamping(h[:32])

	Y := edwards25519.NewIdentityPoint().ScalarBaseMult(x)
	copy(pk[:], Y.Bytes())
	copy(sk[:], seed[:])
	copy(sk[SeedSize:], pk[:])
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

// PrefixUint64 returns the first 8 bytes of o interpreted as a big-endian
// unsigned integer.
//
// The result is a lossy prefix of the 64-byte VRF output, intended for
// sortition-style threshold comparisons. Use o directly when the full VRF
// output is required.
func (o Output) PrefixUint64() uint64 {
	return binary.BigEndian.Uint64(o[:8])
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
	Y, x, truncatedHash, err := sk.expand()
	if err != nil {
		return Proof{}, err
	}
	return vrfProve(Y, x, truncatedHash, message)
}

// Verify verifies proof over message and returns the VRF output if valid.
//
// The method argument order is proof, message. The package-level Verify uses
// pub, message, proof to match crypto/ed25519.Verify.
func (pk PublicKey) Verify(proof Proof, message []byte) (Output, error) {
	return vrfVerifyAndHash(pk[:], proof[:], message)
}

func (sk PrivateKey) expand() (*edwards25519.Point, *edwards25519.Scalar, []byte, error) {
	h := sha512.Sum512(sk[:SeedSize])
	x := edwards25519.NewScalar()
	x.SetBytesWithClamping(h[:32])

	Y := edwards25519.NewIdentityPoint()
	if _, err := Y.SetBytes(sk[SeedSize:]); err != nil {
		return nil, nil, nil, fmt.Errorf("%w: private key public half: %v", ErrInvalidPublicKey, err)
	}
	return Y, x, h[32:], nil
}

func vrfVerifyAndHash(pk, proof, message []byte) (Output, error) {
	Y := &edwards25519.Point{}
	if _, err := Y.SetBytes(pk); err != nil {
		return Output{}, fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
	}
	if isSmallOrder(Y) {
		return Output{}, ErrSmallOrderPoint
	}

	Gamma, ok, err := vrfVerify(Y, proof, message)
	if err != nil {
		return Output{}, err
	}
	if !ok {
		return Output{}, ErrVerifyFailed
	}
	return proofToHashPoint(Gamma), nil
}

func vrfProve(Y *edwards25519.Point, x *edwards25519.Scalar, truncatedHash []byte, message []byte) (Proof, error) {
	var proof Proof

	H, err := encodeToCurve(Y, message)
	if err != nil {
		return Proof{}, err
	}
	Gamma := new(edwards25519.Point).ScalarMult(x, H)
	k := nonceGeneration(truncatedHash, H)
	kB := new(edwards25519.Point).ScalarBaseMult(k)
	kH := new(edwards25519.Point).ScalarMult(k, H)
	c := challenge(Y, H, Gamma, kB, kH)
	s := edwards25519.NewScalar().MultiplyAdd(c, x, k)

	copy(proof[:], Gamma.Bytes())
	copy(proof[32:], c.Bytes()[:16])
	copy(proof[48:], s.Bytes())
	return proof, nil
}

func vrfVerify(Y *edwards25519.Point, pi []byte, message []byte) (*edwards25519.Point, bool, error) {
	Gamma, cBytes, s, err := decodeProof(pi)
	if err != nil {
		return nil, false, err
	}

	H, err := encodeToCurve(Y, message)
	if err != nil {
		return nil, false, err
	}
	c := scalarFromTruncated(cBytes)

	// Y, c, and s are all derived from public inputs, so using variable-time
	// multiplication here does not reveal secret material.
	negC := new(edwards25519.Scalar).Negate(c)
	U := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(negC, Y, s)

	sH := new(edwards25519.Point).ScalarMult(s, H)
	cGamma := new(edwards25519.Point).ScalarMult(c, Gamma)
	V := new(edwards25519.Point).Subtract(sH, cGamma)

	cPrime := challenge(Y, H, Gamma, U, V)
	return Gamma, subtle.ConstantTimeCompare(cBytes[:], cPrime.Bytes()[:16]) == 1, nil
}

func encodeToCurve(Y *edwards25519.Point, message []byte) (*edwards25519.Point, error) {
	u, err := hashToField(Y.Bytes(), message)
	if err != nil {
		return nil, err
	}
	Q, err := mapToCurve(u)
	if err != nil {
		return nil, err
	}
	return new(edwards25519.Point).MultByCofactor(Q), nil
}

func hashToField(parts ...[]byte) (*field.Element, error) {
	uniform := expandMessageXMD48(parts...)
	return fieldFromWideBytes(uniform[:])
}

func fieldFromWideBytes(in []byte) (*field.Element, error) {
	if len(in) != 48 {
		return nil, fmt.Errorf("hash_to_field: got %d bytes, want 48", len(in))
	}
	var wide [64]byte
	for i := range in {
		wide[i] = in[len(in)-1-i]
	}
	u := new(field.Element)
	if _, err := u.SetWideBytes(wide[:]); err != nil {
		return nil, err
	}
	return u, nil
}

func mapToCurve(u *field.Element) (*edwards25519.Point, error) {
	xMn, xMd, yMn, yMd := mapToCurveElligator2Curve25519(u)

	xn := new(field.Element).Multiply(xMn, yMd)
	xn.Multiply(xn, sqrtMinus486664FE)
	xd := new(field.Element).Multiply(xMd, yMn)
	yn := new(field.Element).Subtract(xMn, xMd)
	yd := new(field.Element).Add(xMn, xMd)

	if new(field.Element).Multiply(xd, yd).Equal(new(field.Element).Zero()) == 1 {
		xn.Zero()
		xd.One()
		yn.One()
		yd.One()
	}

	x := new(field.Element).Multiply(xn, new(field.Element).Invert(xd))
	y := new(field.Element).Multiply(yn, new(field.Element).Invert(yd))
	enc := y.Bytes()
	enc[31] &^= 0x80
	if sgn0(x) == 1 {
		enc[31] |= 0x80
	}

	p := new(edwards25519.Point)
	if _, err := p.SetBytes(enc); err != nil {
		return nil, err
	}
	return p, nil
}

func mapToCurveElligator2Curve25519(u *field.Element) (xn, xd, yn, yd *field.Element) {
	tv1 := new(field.Element).Square(u)
	tv1.Add(tv1, tv1)
	xd = new(field.Element).Add(tv1, oneFE)
	x1n := new(field.Element).Set(negCurve25519J)

	invXD := new(field.Element).Invert(xd)
	x1 := new(field.Element).Multiply(x1n, invXD)
	x2n := new(field.Element).Multiply(x1n, tv1)

	x1Squared := new(field.Element).Square(x1)
	gx1 := new(field.Element).Multiply(x1, x1Squared)
	gx1.Add(gx1, new(field.Element).Multiply(curve25519J, x1Squared))
	gx1.Add(gx1, x1)

	gx2 := new(field.Element).Multiply(tv1, gx1)
	y1, e2 := new(field.Element).SqrtRatio(gx1, oneFE)
	y2, _ := new(field.Element).SqrtRatio(gx2, oneFE)

	xn = new(field.Element).Select(x1n, x2n, e2)
	y := new(field.Element).Select(y1, y2, e2)
	e4 := sgn0(y)
	y.Select(new(field.Element).Negate(y), y, e2^e4)

	return xn, xd, y, new(field.Element).One()
}

func sqrtMinus486664() *field.Element {
	minus486664 := new(field.Element).Negate(new(field.Element).Mult32(oneFE, 486664))
	c, wasSquare := new(field.Element).SqrtRatio(minus486664, oneFE)
	if wasSquare != 1 {
		panic("vrf: sqrt(-486664) does not exist")
	}
	if sgn0(c) == 1 {
		c.Negate(c)
	}
	return c
}

func sgn0(x *field.Element) int {
	return int(x.Bytes()[0] & 1)
}

func expandMessageXMD(msg, dst []byte, lenInBytes int) []byte {
	h := func(parts ...[]byte) []byte {
		sum := sha512.New()
		for _, p := range parts {
			sum.Write(p)
		}
		return sum.Sum(nil)
	}

	const bInBytes = 64
	const rInBytes = 128
	ell := (lenInBytes + bInBytes - 1) / bInBytes
	if ell > 255 {
		panic("vrf: expand_message_xmd output too long")
	}

	dstPrime := make([]byte, len(dst)+1)
	copy(dstPrime, dst)
	dstPrime[len(dst)] = byte(len(dst))

	zPad := make([]byte, rInBytes)
	libStr := make([]byte, 2)
	binary.BigEndian.PutUint16(libStr, uint16(lenInBytes))

	b0 := h(zPad, msg, libStr, []byte{0}, dstPrime)
	bi := h(b0, []byte{1}, dstPrime)

	out := make([]byte, 0, ell*bInBytes)
	out = append(out, bi...)
	for i := 2; i <= ell; i++ {
		x := make([]byte, bInBytes)
		for j := range x {
			x[j] = b0[j] ^ bi[j]
		}
		bi = h(x, []byte{byte(i)}, dstPrime)
		out = append(out, bi...)
	}
	return out[:lenInBytes]
}

func expandMessageXMD48(parts ...[]byte) [48]byte {
	var zPad [128]byte
	var dstPrime [len(hashToCurveDSTString) + 1]byte
	copy(dstPrime[:], hashToCurveDSTString)
	dstPrime[len(hashToCurveDSTString)] = byte(len(hashToCurveDSTString))
	lenStr := [2]byte{0, 48}
	zero := [1]byte{0}
	one := [1]byte{1}

	h := sha512.New()
	h.Write(zPad[:])
	for _, part := range parts {
		h.Write(part)
	}
	h.Write(lenStr[:])
	h.Write(zero[:])
	h.Write(dstPrime[:])
	var b0 [sha512.Size]byte
	h.Sum(b0[:0])

	h.Reset()
	h.Write(b0[:])
	h.Write(one[:])
	h.Write(dstPrime[:])
	var b1 [sha512.Size]byte
	h.Sum(b1[:0])

	var out [48]byte
	copy(out[:], b1[:48])
	return out
}

func nonceGeneration(truncatedHash []byte, H *edwards25519.Point) *edwards25519.Scalar {
	h := sha512.New()
	h.Write(truncatedHash)
	h.Write(H.Bytes())
	k := edwards25519.NewScalar()
	k.SetUniformBytes(h.Sum(nil))
	return k
}

func challenge(P1, P2, P3, P4, P5 *edwards25519.Point) *edwards25519.Scalar {
	var input [2 + 32*5 + 1]byte
	input[0] = vrfSuite
	input[1] = 0x02
	copy(input[2:], P1.Bytes())
	copy(input[34:], P2.Bytes())
	copy(input[66:], P3.Bytes())
	copy(input[98:], P4.Bytes())
	copy(input[130:], P5.Bytes())
	input[162] = 0x00

	sum := sha512.Sum512(input[:])
	var truncated [16]byte
	copy(truncated[:], sum[:16])
	return scalarFromTruncated(truncated)
}

func scalarFromTruncated(b [16]byte) *edwards25519.Scalar {
	var s [32]byte
	copy(s[:], b[:])
	out := edwards25519.NewScalar()
	if _, err := out.SetCanonicalBytes(s[:]); err != nil {
		panic("vrf: invalid truncated scalar")
	}
	return out
}

func decodeProof(pi []byte) (*edwards25519.Point, [16]byte, *edwards25519.Scalar, error) {
	var c [16]byte
	if len(pi) != ProofSize {
		return nil, c, nil, fmt.Errorf("%w: proof must be %d bytes, got %d", ErrInvalidProof, ProofSize, len(pi))
	}

	Gamma := new(edwards25519.Point)
	if _, err := Gamma.SetBytes(pi[:32]); err != nil {
		return nil, c, nil, fmt.Errorf("%w: invalid Gamma point: %v", ErrInvalidProof, err)
	}

	copy(c[:], pi[32:48])

	s := edwards25519.NewScalar()
	if _, err := s.SetCanonicalBytes(pi[48:80]); err != nil {
		return nil, c, nil, fmt.Errorf("%w: non-canonical scalar", ErrInvalidProof)
	}

	return Gamma, c, s, nil
}

func proofToHash(pi []byte) ([]byte, error) {
	Gamma, _, _, err := decodeProof(pi)
	if err != nil {
		return nil, err
	}
	output := proofToHashPoint(Gamma)
	return output[:], nil
}

func proofToHashPoint(Gamma *edwards25519.Point) Output {
	var input [35]byte
	input[0] = vrfSuite
	input[1] = 0x03
	Gamma.MultByCofactor(Gamma)
	copy(input[2:], Gamma.Bytes())
	input[34] = 0x00

	return Output(sha512.Sum512(input[:]))
}

func isSmallOrder(p *edwards25519.Point) bool {
	return new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 1
}
