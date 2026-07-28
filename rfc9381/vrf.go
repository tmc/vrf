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

	// SuiteID is the suite_string octet, which domain-separates this suite's
	// hash inputs.
	//
	// It is 0x04 here and in draft03: the octet names the curve and hash, not
	// the construction, so it cannot tell the two suites apart. Use it to read
	// or write a suite octet on the wire. Keeping the suites from being mixed
	// is the job of their distinct proof and key types.
	SuiteID byte = 0x04

	hashToCurveDSTString = "ECVRF_edwards25519_XMD:SHA-512_ELL2_NU_\x04"
)

var (
	// ErrInvalidPublicKey reports a malformed public key.
	ErrInvalidPublicKey = errors.New("vrf: invalid public key")

	// ErrSmallOrderPoint reports a public key with small order. It wraps
	// ErrInvalidPublicKey, since such a key is a species of invalid key.
	ErrSmallOrderPoint = fmt.Errorf("%w: small-order point", ErrInvalidPublicKey)

	// ErrInvalidProof reports a malformed VRF proof.
	ErrInvalidProof = errors.New("vrf: invalid proof")

	// ErrVerifyFailed reports a proof that does not verify.
	ErrVerifyFailed = errors.New("vrf: proof verification failed")
)

// PublicKey represents an RFC 9381 VRF public key.
//
// The zero value is not a usable key. Obtain one from GenerateKey,
// ParsePublicKey, or (PrivateKey).PublicKey.
type PublicKey [PublicKeySize]byte

// PrivateKey represents an RFC 9381 VRF private key.
//
// The zero value is not a usable key: its public half decodes to the identity
// point, so Prove reports ErrSmallOrderPoint. Obtain one from GenerateKey or
// NewKeyFromSeed.
//
// Its methods take a pointer receiver so that calling one does not copy the
// key material. A PrivateKey must therefore be addressable to call them: assign
// it to a variable rather than calling a method on a function result directly.
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

// GenerateKey generates a new RFC 9381 VRF key pair using random.
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
// It rejects encodings that do not decode to a curve point, and points of small
// order. Because PublicKey is an array type, a key obtained by conversion
// rather than through ParsePublicKey is unchecked; Verify and Prove validate
// again for that reason.
func ParsePublicKey(b []byte) (PublicKey, error) {
	var pk PublicKey
	if len(b) != PublicKeySize {
		return pk, fmt.Errorf("%w: must be %d bytes, got %d", ErrInvalidPublicKey, PublicKeySize, len(b))
	}
	var Y edwards25519.Point
	if _, err := Y.SetBytes(b); err != nil {
		return pk, fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
	}
	if isSmallOrder(&Y) {
		return pk, ErrSmallOrderPoint
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

// Public returns the public key corresponding to sk, as a [crypto.PublicKey].
//
// Use [PrivateKey.PublicKey] to obtain the concrete type without a type
// assertion.
func (sk *PrivateKey) Public() crypto.PublicKey {
	return sk.PublicKey()
}

// PublicKey returns the public key corresponding to sk.
func (sk *PrivateKey) PublicKey() PublicKey {
	var pk PublicKey
	copy(pk[:], sk[SeedSize:])
	return pk
}

// Seed returns a copy of sk's private key seed.
func (sk *PrivateKey) Seed() []byte {
	seed := make([]byte, SeedSize)
	copy(seed, sk[:SeedSize])
	return seed
}

// Equal reports whether sk and x contain the same private key.
//
// x may be a PrivateKey or a *PrivateKey.
func (sk *PrivateKey) Equal(x crypto.PrivateKey) bool {
	var other *PrivateKey
	switch v := x.(type) {
	case PrivateKey:
		other = &v
	case *PrivateKey:
		other = v
	}
	if other == nil {
		return false
	}
	return subtle.ConstantTimeCompare(sk[:], other[:]) == 1
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

// Hash returns the VRF output encoded in p without verifying it.
//
// This is ECVRF_proof_to_hash from RFC 9381, Section 5.2. It decodes the proof
// and hashes its gamma point, and reports an error only when the proof is
// malformed.
//
// Hash does not authenticate anything. It takes no public key and no message,
// so it cannot tell a genuine proof from one an attacker made up: any proof
// that decodes yields some output. Use Verify, which returns the same output
// only when the proof holds. Reach for Hash only when the proof has already
// been verified, or when the output is not being trusted.
func (p Proof) Hash() (Output, error) {
	return proofToHash(p[:])
}

// Verify verifies proof over msg under pub and returns the VRF output if the
// proof is valid.
//
// Arguments are in crypto/ed25519.Verify order: public key, message, proof.
func Verify(pub PublicKey, msg []byte, proof Proof) (Output, error) {
	return vrfVerifyAndHash(pub[:], proof[:], msg)
}

// Prove generates a VRF proof for message.
func (sk *PrivateKey) Prove(message []byte) (Proof, error) {
	var Y edwards25519.Point
	var x edwards25519.Scalar
	var truncatedHash [32]byte
	if err := sk.expand(&Y, &x, &truncatedHash); err != nil {
		return Proof{}, err
	}
	return vrfProve(&Y, &x, truncatedHash, message)
}

func (sk *PrivateKey) expand(Y *edwards25519.Point, x *edwards25519.Scalar, truncatedHash *[32]byte) error {
	h := sha512.Sum512(sk[:SeedSize])
	x.SetBytesWithClamping(h[:32])

	if _, err := Y.SetBytes(sk[SeedSize:]); err != nil {
		return fmt.Errorf("%w: private key public half: %v", ErrInvalidPublicKey, err)
	}
	if isSmallOrder(Y) {
		return ErrSmallOrderPoint
	}
	copy(truncatedHash[:], h[32:])
	return nil
}

func vrfVerifyAndHash(pk, proof, message []byte) (Output, error) {
	Y := &edwards25519.Point{}
	if _, err := Y.SetBytes(pk); err != nil {
		return Output{}, fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
	}
	if isSmallOrder(Y) {
		return Output{}, ErrSmallOrderPoint
	}

	var Gamma edwards25519.Point
	ok, err := vrfVerify(&Gamma, Y, proof, message)
	if err != nil {
		return Output{}, err
	}
	if !ok {
		return Output{}, ErrVerifyFailed
	}
	return proofToHashPoint(&Gamma), nil
}

func vrfProve(Y *edwards25519.Point, x *edwards25519.Scalar, truncatedHash [32]byte, message []byte) (Proof, error) {
	var proof Proof

	var H edwards25519.Point
	if err := encodeToCurve(&H, Y, message); err != nil {
		return Proof{}, err
	}
	Gamma := new(edwards25519.Point).ScalarMult(x, &H)
	var k edwards25519.Scalar
	nonceGeneration(&k, truncatedHash, &H)
	kB := new(edwards25519.Point).ScalarBaseMult(&k)
	kH := new(edwards25519.Point).ScalarMult(&k, &H)
	var c edwards25519.Scalar
	challenge(&c, Y, &H, Gamma, kB, kH)
	var s edwards25519.Scalar
	s.MultiplyAdd(&c, x, &k)

	copy(proof[:], Gamma.Bytes())
	copy(proof[32:], c.Bytes()[:16])
	copy(proof[48:], s.Bytes())
	return proof, nil
}

func vrfVerify(Gamma, Y *edwards25519.Point, pi []byte, message []byte) (bool, error) {
	var s edwards25519.Scalar
	cBytes, err := decodeProof(Gamma, &s, pi)
	if err != nil {
		return false, err
	}

	var H edwards25519.Point
	if err := encodeToCurve(&H, Y, message); err != nil {
		return false, err
	}
	var c edwards25519.Scalar
	scalarFromTruncated(&c, cBytes)

	// Y, c, and s are all derived from public inputs, so using variable-time
	// multiplication here does not reveal secret material.
	negC := new(edwards25519.Scalar).Negate(&c)
	U := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(negC, Y, &s)

	sH := new(edwards25519.Point).ScalarMult(&s, &H)
	cGamma := new(edwards25519.Point).ScalarMult(&c, Gamma)
	V := new(edwards25519.Point).Subtract(sH, cGamma)

	var cPrime edwards25519.Scalar
	challenge(&cPrime, Y, &H, Gamma, U, V)
	return subtle.ConstantTimeCompare(cBytes[:], cPrime.Bytes()[:16]) == 1, nil
}

func encodeToCurve(out, Y *edwards25519.Point, message []byte) error {
	var u field.Element
	if err := hashToField(&u, Y.Bytes(), message); err != nil {
		return err
	}
	var Q edwards25519.Point
	if err := mapToCurve(&Q, &u); err != nil {
		return err
	}
	out.MultByCofactor(&Q)
	return nil
}

func hashToField(out *field.Element, parts ...[]byte) error {
	uniform := expandMessageXMD48(parts...)
	return fieldFromWideBytes(out, uniform[:])
}

func fieldFromWideBytes(out *field.Element, in []byte) error {
	if len(in) != 48 {
		return fmt.Errorf("hash_to_field: got %d bytes, want 48", len(in))
	}
	var wide [64]byte
	for i := range in {
		wide[i] = in[len(in)-1-i]
	}
	if _, err := out.SetWideBytes(wide[:]); err != nil {
		return err
	}
	return nil
}

func mapToCurve(out *edwards25519.Point, u *field.Element) error {
	var xMn, xMd, yMn, yMd field.Element
	mapToCurveElligator2Curve25519(&xMn, &xMd, &yMn, &yMd, u)

	var xn, xd, yn, yd field.Element
	xn.Multiply(&xMn, &yMd)
	xn.Multiply(&xn, sqrtMinus486664FE)
	xd.Multiply(&xMd, &yMn)
	yn.Subtract(&xMn, &xMd)
	yd.Add(&xMn, &xMd)

	var product, zero field.Element
	if product.Multiply(&xd, &yd).Equal(zero.Zero()) == 1 {
		xn.Zero()
		xd.One()
		yn.One()
		yd.One()
	}

	var x, y, inverse field.Element
	x.Multiply(&xn, inverse.Invert(&xd))
	y.Multiply(&yn, inverse.Invert(&yd))
	enc := y.Bytes()
	enc[31] &^= 0x80
	if sgn0(&x) == 1 {
		enc[31] |= 0x80
	}

	if _, err := out.SetBytes(enc); err != nil {
		return err
	}
	return nil
}

func mapToCurveElligator2Curve25519(xn, xd, yn, yd, u *field.Element) {
	var tv1 field.Element
	tv1.Square(u)
	tv1.Add(&tv1, &tv1)
	xd.Add(&tv1, oneFE)

	var x1n, invXD, x1, x2n field.Element
	x1n.Set(negCurve25519J)
	invXD.Invert(xd)
	x1.Multiply(&x1n, &invXD)
	x2n.Multiply(&x1n, &tv1)

	var x1Squared, gx1, curveTerm field.Element
	x1Squared.Square(&x1)
	gx1.Multiply(&x1, &x1Squared)
	curveTerm.Multiply(curve25519J, &x1Squared)
	gx1.Add(&gx1, &curveTerm)
	gx1.Add(&gx1, &x1)

	var gx2, y1, y2 field.Element
	gx2.Multiply(&tv1, &gx1)
	_, e2 := y1.SqrtRatio(&gx1, oneFE)
	y2.SqrtRatio(&gx2, oneFE)

	xn.Select(&x1n, &x2n, e2)
	var y, negY field.Element
	y.Select(&y1, &y2, e2)
	e4 := sgn0(&y)
	negY.Negate(&y)
	y.Select(&negY, &y, e2^e4)

	yn.Set(&y)
	yd.One()
}

func sqrtMinus486664() *field.Element {
	minus486664 := new(field.Element).Negate(new(field.Element).Mult32(oneFE, 486664))
	c, wasSquare := new(field.Element).SqrtRatio(minus486664, oneFE)
	if wasSquare != 1 {
		// Unreachable: -486664 is a quadratic residue mod 2^255-19, which is
		// what makes the Montgomery-to-Edwards map well defined for this curve.
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

// expandMessageXMD is the generic expand_message_xmd from RFC 9380 Section 5.3.
// Nothing in the package calls it: hashToField uses expandMessageXMD48, which
// is specialized to the single output length this suite needs. It is kept
// because TestExpandMessageXMD48 checks the specialized version against it
// differentially, and a specialization is only as trustworthy as the general
// implementation it is compared with.
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

func nonceGeneration(out *edwards25519.Scalar, truncatedHash [32]byte, H *edwards25519.Point) {
	h := sha512.New()
	h.Write(truncatedHash[:])
	h.Write(H.Bytes())
	var sum [sha512.Size]byte
	h.Sum(sum[:0])
	out.SetUniformBytes(sum[:])
}

func challenge(out *edwards25519.Scalar, P1, P2, P3, P4, P5 *edwards25519.Point) {
	var input [2 + 32*5 + 1]byte
	input[0] = SuiteID
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
	scalarFromTruncated(out, truncated)
}

func scalarFromTruncated(out *edwards25519.Scalar, b [16]byte) {
	var s [32]byte
	copy(s[:], b[:])
	if _, err := out.SetCanonicalBytes(s[:]); err != nil {
		panic("vrf: invalid truncated scalar")
	}
}

func decodeProof(Gamma *edwards25519.Point, s *edwards25519.Scalar, pi []byte) ([16]byte, error) {
	var c [16]byte
	if len(pi) != ProofSize {
		return c, fmt.Errorf("%w: proof must be %d bytes, got %d", ErrInvalidProof, ProofSize, len(pi))
	}

	if _, err := Gamma.SetBytes(pi[:32]); err != nil {
		return c, fmt.Errorf("%w: invalid Gamma point: %v", ErrInvalidProof, err)
	}

	copy(c[:], pi[32:48])

	if _, err := s.SetCanonicalBytes(pi[48:80]); err != nil {
		return c, fmt.Errorf("%w: non-canonical scalar", ErrInvalidProof)
	}

	return c, nil
}

func proofToHash(pi []byte) (Output, error) {
	var Gamma edwards25519.Point
	var s edwards25519.Scalar
	if _, err := decodeProof(&Gamma, &s, pi); err != nil {
		return Output{}, err
	}
	return proofToHashPoint(&Gamma), nil
}

func proofToHashPoint(Gamma *edwards25519.Point) Output {
	var input [35]byte
	input[0] = SuiteID
	input[1] = 0x03
	Gamma.MultByCofactor(Gamma)
	copy(input[2:], Gamma.Bytes())
	input[34] = 0x00

	return Output(sha512.Sum512(input[:]))
}

func isSmallOrder(p *edwards25519.Point) bool {
	return new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 1
}
