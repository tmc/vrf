// Package rfc9381 is an incomplete ECVRF-EDWARDS25519-SHA512-ELL2
// implementation.
//
// This package is not ready for use. It is kept in-tree as a work area for the
// RFC 9381 port; design.md lists the known spec deviations that must be fixed
// before this package is published as an implementation.
package rfc9381

import (
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"math/big"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
)

const (
	// PublicKeySize is the size of a VRF public key in bytes
	PublicKeySize = 32
	// PrivateKeySize is the size of a VRF private key in bytes
	PrivateKeySize = 64
	// ProofSize is the size of a VRF proof in bytes
	ProofSize = 80
	// OutputSize is the size of VRF output in bytes
	OutputSize = 64

	// vrfSuite from RFC 9381 for ECVRF-EDWARDS25519-SHA512-ELL2
	vrfSuite = 0x04
)

var (
	// hashToCurveDST is the Domain Separation Tag for hash-to-curve
	// RFC 9381 Section 5.1 specifies: "This ciphersuite uses the hash_to_curve suite ... edwards25519_XMD:SHA-512_ELL2_RO_"
	hashToCurveDST = []byte("edwards25519_XMD:SHA-512_ELL2_RO_")

	// curve25519P is 2^255 - 19
	curve25519P, _ = new(big.Int).SetString("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)
)

// PublicKey represents a VRF public key
type PublicKey [PublicKeySize]byte

// PrivateKey represents a VRF private key
type PrivateKey [PrivateKeySize]byte

// Proof represents a VRF proof
type Proof [ProofSize]byte

// Output represents VRF output hash
type Output [OutputSize]byte

// Keygen generates a VRF key pair from a 32-byte seed
func Keygen(seed [32]byte) (PublicKey, PrivateKey) {
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
		return nil, nil, nil, err
	}

	return Y, xScalar, truncHashedSk, nil
}

// vrfVerifyAndHash verifies a VRF proof and returns the output hash
func vrfVerifyAndHash(pk []byte, proof []byte, message []byte) ([]byte, error) {
	Y := &edwards25519.Point{}
	if _, err := Y.SetBytes(pk); err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	if Y.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return nil, fmt.Errorf("public key is identity element")
	}

	// Verify the proof
	ok, err := vrfVerify(Y, proof, message)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("proof verification failed")
	}

	// Convert proof to hash
	return proofToHash(proof)
}

// vrfProve constructs a VRF proof for a message
func vrfProve(Y *edwards25519.Point, xScalar *edwards25519.Scalar, truncHashedSk []byte, message []byte) (Proof, error) {
	var proof Proof

	// Hash message to curve point
	input := make([]byte, 32+len(message))
	copy(input[:32], Y.Bytes())
	copy(input[32:], message)

	H, err := hashToCurve(input)
	if err != nil {
		return Proof{}, err
	}

	// Gamma = x * H
	Gamma := new(edwards25519.Point).ScalarMult(xScalar, H)

	// k = nonceGeneration(SK, H)
	k := nonceGeneration(truncHashedSk, H)

	// kB = k * B
	kB := edwards25519.NewIdentityPoint().ScalarBaseMult(k)

	// kH = k * H
	kH := edwards25519.NewIdentityPoint().ScalarMult(k, H)

	// c = hash_points(H, Gamma, kB, kH)
	c := hashPoints(H, Gamma, kB, kH)

	// s = c*x + k (mod q)
	s := edwards25519.NewScalar()
	s.MultiplyAdd(c, xScalar, k)

	// Encode proof
	copy(proof[:], Gamma.Bytes())
	copy(proof[32:], c.Bytes()[:16])
	copy(proof[48:], s.Bytes())

	return proof, nil
}

// vrfVerify verifies a VRF proof
func vrfVerify(Y *edwards25519.Point, pi []byte, message []byte) (bool, error) {
	Gamma, cBytes, sBytes, err := decodeProof(pi)
	if err != nil {
		return false, err
	}

	input := make([]byte, 32+len(message))
	copy(input[:32], Y.Bytes())
	copy(input[32:], message)

	H, err := hashToCurve(input)
	if err != nil {
		return false, err
	}

	cBytes64 := make([]byte, 64)
	copy(cBytes64, cBytes)
	c := edwards25519.NewScalar()
	c.SetUniformBytes(cBytes64)

	sBytes64 := make([]byte, 64)
	copy(sBytes64, sBytes)
	s := edwards25519.NewScalar()
	s.SetUniformBytes(sBytes64)

	cY := new(edwards25519.Point).ScalarMult(c, Y)
	sB := new(edwards25519.Point).ScalarBaseMult(s)
	U := new(edwards25519.Point).Subtract(sB, cY)

	sH := new(edwards25519.Point).ScalarMult(s, H)
	cGamma := new(edwards25519.Point).ScalarMult(c, Gamma)
	V := new(edwards25519.Point).Subtract(sH, cGamma)

	cprime := hashPoints(H, Gamma, U, V)

	return subtle.ConstantTimeCompare(cBytes, cprime.Bytes()[:16]) == 1, nil
}

func hashToCurve(message []byte) (*edwards25519.Point, error) {
	u0, u1 := hashToField(message)

	Q0, err := mapToCurve(u0)
	if err != nil {
		return nil, err
	}

	Q1, err := mapToCurve(u1)
	if err != nil {
		return nil, err
	}

	R := new(edwards25519.Point).Add(Q0, Q1)
	R.MultByCofactor(R) // clear_cofactor
	return R, nil
}

func hashToField(msg []byte) ([]byte, []byte) {
	// L = 48 bytes (384 bits) logic per RFC 9380 Section 8.5 for edwards25519
	const L = 48
	uniformBytes := expandMessageXMD(msg, hashToCurveDST, 2*L)

	u0 := reduceModP(uniformBytes[:L])
	u1 := reduceModP(uniformBytes[L:])

	return u0, u1
}

func reduceModP(b []byte) []byte {
	num := new(big.Int).SetBytes(b)
	num.Mod(num, curve25519P)

	res := make([]byte, 32)
	bNum := num.Bytes()
	for i := 0; i < len(bNum) && i < 32; i++ {
		res[i] = bNum[len(bNum)-1-i]
	}
	// Note: bNum is big-endian, we want little-endian for SetBytes (if that's what we decided).
	// Wait, filippo.io/edwards25519/field SetBytes doc says "The value is in little-endian order".
	// Yes, reversing bNum is correct (bNum[0] is most significant).
	return res
}

func mapToCurve(uBytes []byte) (*edwards25519.Point, error) {
	u := new(field.Element)
	if _, err := u.SetBytes(uBytes); err != nil {
		return nil, err
	}

	// Elligator 2 mapping adapted from standard logic (and matching vrf.go's optimized steps)

	one := new(field.Element).One()

	// tv1 = u^2
	tv1 := new(field.Element).Square(u)

	// tv1 = 2 * tv1
	tv1.Add(tv1, tv1)

	// tv1 = tv1 + 1
	tv1.Add(tv1, one)

	// tv1 = 1 / tv1
	tv1.Invert(tv1)

	// x = -A * tv1
	const curve25519A = 486662
	x := new(field.Element).Mult32(tv1, curve25519A)
	x.Negate(x)

	// x2 = x^2
	x2 := new(field.Element).Square(x)
	// x3 = x^3
	x3 := new(field.Element).Multiply(x, x2)

	// e = x^3 + A*x^2 + x
	e := new(field.Element)
	e.Mult32(x2, curve25519A)
	e.Add(e, x3)
	e.Add(e, x)

	// Check if e is quadratic residue
	eChi := chi25519(e)
	eBytes := eChi.Bytes()

	// eIsMinus1 is 1 if e is non-square, 0 if square (if chi returns -1 for square... wait)
	// chi25519 logic needs to be verified.
	// If chi returns Legendre symbol:
	// 1: square
	// -1 (all ones): non-square
	// 0: zero
	//
	// vrf.go: eIsMinus1 := int(eBytes[1] & 1)
	// If eBytes is all ones (-1), eIsMinus1 is 1 (0xFF & 1).
	// usage: x.Select(x, negx, eIsNotMinus1)
	// If eIsMinus1 (non-square), eIsNotMinus1 = 0 -> Selects negx.
	// So: if non-square, negx.
	// Elligator 2: if e not square, x = -x. Correct.

	// eIsMinus1 logic was based on eBytes[1] in vrf.go.
	// In little-endian eBytes[0] is 1 for square (1) and 0 for non-square (p-1 ends in 0xEC).
	// So eBytes[0] & 1 is 1 if SQUARE (which corresponds to eIsNotMinus1).
	eIsNotMinus1 := int(eBytes[0] & 1)

	negx := new(field.Element).Negate(x)
	x.Select(x, negx, eIsNotMinus1)

	// x2 = 0
	x2.Zero()
	// if eIsNotMinus1 (square), x2 = A. Else x2 = 0.
	// Wait, vrf.go: x2.Select(x2, curve25519AElement, eIsNotMinus1)
	// curve25519AElement = A * 1.
	curve25519AElement := new(field.Element).Mult32(one, curve25519A)
	x2.Select(x2, curve25519AElement, eIsNotMinus1)

	// x = x - x2
	x.Subtract(x, x2)

	// Convert to Edwards coordinates: yed = (x-1)/(x+1)
	xPlusOne := new(field.Element).Add(x, one)
	xMinusOne := new(field.Element).Subtract(x, one)
	xPlusOneInv := new(field.Element).Invert(xPlusOne)
	yed := new(field.Element).Multiply(xMinusOne, xPlusOneInv)

	s := yed.Bytes()

	// Sign bit of u?
	// Elligator 2: "Choose the solution where x ... " or "Sign of ... is same as sign of u"?
	// RFC 9380: "Sign of resulting point Y coordinate matches sign of u".
	// existing vrf.go: s[31] |= xSign (where xSign came from input r).
	// We need sign of u.
	// u is [32]byte little endian. Sign bit is uBytes[31] & 0x80 (if standard edwards25519 encoding, sign is high bit of last byte).
	// Yes, `filippo.io/edwards25519` uses standard encoding.
	xSign := uBytes[31] & 0x80
	s[31] |= xSign

	// Decode
	p3 := &edwards25519.Point{}
	if _, err := p3.SetBytes(s); err != nil {
		return nil, err
	}

	return p3, nil
}

func expandMessageXMD(msg []byte, dst []byte, lenInBytes int) []byte {
	H := func(data ...[]byte) []byte {
		h := sha512.New()
		for _, d := range data {
			h.Write(d)
		}
		return h.Sum(nil)
	}

	const bInBytes = 64
	const sInBytes = 128

	ell := (lenInBytes + bInBytes - 1) / bInBytes
	if ell > 255 {
		panic("expandMessageXMD: output too long")
	}

	dstPrime := make([]byte, len(dst)+1)
	copy(dstPrime, dst)
	dstPrime[len(dst)] = byte(len(dst))

	zPad := make([]byte, sInBytes)
	libStr := make([]byte, 2)
	binary.BigEndian.PutUint16(libStr, uint16(lenInBytes))

	b0 := H(zPad, msg, libStr, []byte{0}, dstPrime)

	b := make([][]byte, ell)
	b[0] = H(b0, []byte{1}, dstPrime)

	for i := 1; i < ell; i++ {
		xorVal := make([]byte, bInBytes)
		for j := 0; j < bInBytes; j++ {
			xorVal[j] = b0[j] ^ b[i-1][j]
		}
		b[i] = H(xorVal, []byte{byte(i + 1)}, dstPrime)
	}

	var out []byte
	for _, blk := range b {
		out = append(out, blk...)
	}

	return out[:lenInBytes]
}

func chi25519(z *field.Element) *field.Element {
	// Calculate z^((p-1)/2)
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

func nonceGeneration(truncHashedSk []byte, H *edwards25519.Point) *edwards25519.Scalar {
	h := sha512.New()
	h.Write(truncHashedSk)
	h.Write(H.Bytes())

	kBytes := h.Sum(nil)
	k := edwards25519.NewScalar()
	k.SetUniformBytes(kBytes)

	return k
}

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

	// Truncate to 32 bytes (16 bytes zero padded? No, vrf.go logic says 16 bytes padded)
	// vrf.go: "copy(result, sum[:16])" then "SetCanonicalBytes"
	// Wait, vrf.go `hashPoints`:
	// result := make([]byte, 32)
	// copy(result, sum[:16])
	// scalar.SetCanonicalBytes(result)

	result := make([]byte, 32)
	copy(result, sum[:16])

	scalar := edwards25519.NewScalar()
	if _, err := scalar.SetCanonicalBytes(result); err != nil {
		panic("invalid scalar from hash")
	}

	return scalar
}

func decodeProof(pi []byte) (*edwards25519.Point, []byte, []byte, error) {
	if len(pi) != ProofSize {
		return nil, nil, nil, fmt.Errorf("proof must be %d bytes, got %d", ProofSize, len(pi))
	}

	Gamma := &edwards25519.Point{}
	if _, err := Gamma.SetBytes(pi[:32]); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid Gamma point: %w", err)
	}

	c := make([]byte, 16)
	copy(c, pi[32:48])

	s := make([]byte, 32)
	copy(s, pi[48:80])

	return Gamma, c, s, nil
}

func proofToHash(pi []byte) ([]byte, error) {
	Gamma, _, _, err := decodeProof(pi)
	if err != nil {
		return nil, err
	}

	var hashInput [34]byte
	hashInput[0] = vrfSuite
	hashInput[1] = 0x03

	Gamma.MultByCofactor(Gamma)
	copy(hashInput[2:], Gamma.Bytes())

	h := sha512.New()
	h.Write(hashInput[:])
	return h.Sum(nil), nil
}
