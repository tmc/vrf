// Package vrf implements ECVRF-EDWARDS25519-SHA512-ELL2 (ciphersuite 0x04) 
// from RFC 9381: Verifiable Random Functions (VRFs)
//
// This is a clean implementation separated from Algorand's go-algorand codebase.
package vrf

import (
	"crypto/sha512"
	"crypto/subtle"
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

	// vrfSuite identifies ECVRF-EDWARDS25519-SHA512-ELL2 ciphersuite
	vrfSuite = 0x04
)

// PublicKey represents a VRF public key
type PublicKey [PublicKeySize]byte

// PrivateKey represents a VRF private key (32-byte seed + 32-byte public key)
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
	
	// Check if public key has small order
	isSmallOrder := (&edwards25519.Point{}).MultByCofactor(Y).Equal(edwards25519.NewIdentityPoint()) == 1
	if isSmallOrder {
		return nil, fmt.Errorf("public key is a small order point")
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

	// c = hash_points(Y, H, Gamma, kB, kH)
	c := hashPoints(Y, H, Gamma, kB, kH)
	
	// s = c*x + k (mod q)
	s := edwards25519.NewScalar()
	s.MultiplyAdd(c, xScalar, k)
	
	// Encode proof as Gamma || c (16 bytes) || s
	copy(proof[:], Gamma.Bytes())
	copy(proof[32:], c.Bytes()[:16])
	copy(proof[48:], s.Bytes())
	
	return proof, nil
}

// hashToCurve hashes a message to a curve point using edwards25519_XMD:SHA-512_ELL2_NU_
func hashToCurve(Y *edwards25519.Point, message []byte) (*edwards25519.Point, error) {
	// Build DST: "ECVRF_" || "edwards25519_XMD:SHA-512_ELL2_NU_" || suite_string
	dst := []byte("ECVRF_edwards25519_XMD:SHA-512_ELL2_NU_")
	dst = append(dst, vrfSuite)

	// string_to_be_hashed = encode_to_curve_salt || alpha_string
	// where encode_to_curve_salt = PK_string for this ciphersuite
	stringToHash := append(Y.Bytes(), message...)

	// expand_message_xmd to get uniform bytes (48 bytes for edwards25519)
	uniformBytes := expandMessageXMD(stringToHash, dst, 48)

	// Apply elligator2 to map to curve point (using all 48 bytes)
	hBytes, err := elligator2(uniformBytes)
	if err != nil {
		return nil, err
	}

	result := &edwards25519.Point{}
	if _, err := result.SetBytes(hBytes); err != nil {
		return nil, err
	}

	return result, nil
}

// expandMessageXMD implements expand_message_xmd from RFC 9380 Section 5.3.1
func expandMessageXMD(msg, dst []byte, lenInBytes int) []byte {
	h := sha512.New()
	bLen := h.Size() // 64 for SHA-512
	ell := (lenInBytes + bLen - 1) / bLen

	// DST_prime = DST || I2OSP(len(DST), 1)
	dstPrime := append(dst, byte(len(dst)))

	// Z_pad = I2OSP(0, r_in_bytes) where r_in_bytes = h.BlockSize()
	zPad := make([]byte, h.BlockSize())

	// b_0 = H(Z_pad || msg || I2OSP(len_in_bytes, 2) || I2OSP(0, 1) || DST_prime)
	h.Reset()
	h.Write(zPad)
	h.Write(msg)
	h.Write([]byte{byte(lenInBytes >> 8), byte(lenInBytes)})
	h.Write([]byte{0})
	h.Write(dstPrime)
	b0 := h.Sum(nil)

	// b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
	h.Reset()
	h.Write(b0)
	h.Write([]byte{1})
	h.Write(dstPrime)
	b1 := h.Sum(nil)

	uniformBytes := make([]byte, 0, lenInBytes)
	uniformBytes = append(uniformBytes, b1...)

	bi := make([]byte, bLen)
	copy(bi, b1)

	for i := 2; i <= ell; i++ {
		// b_i = H(strxor(b_0, b_(i-1)) || I2OSP(i, 1) || DST_prime)
		h.Reset()

		strxor := make([]byte, bLen)
		for j := 0; j < bLen; j++ {
			strxor[j] = b0[j] ^ bi[j]
		}

		h.Write(strxor)
		h.Write([]byte{byte(i)})
		h.Write(dstPrime)
		bi = h.Sum(nil)

		uniformBytes = append(uniformBytes, bi...)
	}

	return uniformBytes[:lenInBytes]
}

// reverseBytes reverses a byte slice
func reverseBytes(b []byte) []byte {
	r := make([]byte, len(b))
	for i := range b {
		r[i] = b[len(b)-1-i]
	}
	return r
}

// elligator2 implements the Elligator2 map from uniform bytes to Edwards25519 point
// Following RFC 9380 Section 6.8.2 and Section 8.5
func elligator2(uniformBytes []byte) ([]byte, error) {
	if len(uniformBytes) != 48 {
		return nil, fmt.Errorf("elligator2: expected 48 bytes, got %d", len(uniformBytes))
	}

	// Constants for curve25519/edwards25519
	// J = 486662, K = 1, Z = 2
	// p = 2^255 - 19
	p := new(big.Int)
	p.SetString("57896044618658097711785492504343953926634992332820282019728792003956564819949", 10)

	// Step 1: Reduce uniform_bytes to field element u mod p
	// Interpret as big-endian integer (OS2IP) per RFC 9380
	uInt := new(big.Int).SetBytes(uniformBytes)
	uInt.Mod(uInt, p)

	// Convert to little-endian for field.Element
	uBigEndian := make([]byte, 32)
	uBytes := uInt.Bytes()
	copy(uBigEndian[32-len(uBytes):], uBytes)
	u := &field.Element{}
	u.SetBytes(reverseBytes(uBigEndian))

	one := new(field.Element).One()
	two := new(field.Element).Add(one, one)

	// Constants: J = 486662, Z = 2
	const J = 486662
	JElement := new(field.Element).Mult32(one, J)

	// Step 2: Compute x1 = -(J/K) * inv0(1 + Z*u^2)
	// Since K=1 and Z=2: x1 = -J / (1 + 2*u^2)
	tv1 := new(field.Element).Square(u)        // u^2
	tv1.Multiply(tv1, two)                      // 2*u^2
	tv1.Add(tv1, one)                           // 1 + 2*u^2
	tv1.Invert(tv1)                             // 1/(1 + 2*u^2)
	x1 := new(field.Element).Multiply(JElement, tv1)  // J/(1 + 2*u^2)
	x1.Negate(x1)                               // -J/(1 + 2*u^2)

	// Step 3: If x1 == 0, set x1 = -J (handle exceptional case)
	// This happens when Z*u^2 == -1
	x1IsZero := x1.Equal(new(field.Element).Zero())
	if x1IsZero == 1 {
		x1.Negate(JElement) // x1 = -J
	}

	// Step 4: Compute gx1 = x1^3 + (J/K)*x1^2 + x1/K^2
	// Since K=1: gx1 = x1^3 + J*x1^2 + x1
	gx1 := new(field.Element).Square(x1)           // x1^2
	gx1Temp := new(field.Element).Multiply(gx1, JElement) // J*x1^2
	gx1.Multiply(gx1, x1)                          // x1^3
	gx1.Add(gx1, gx1Temp)                          // x1^3 + J*x1^2
	gx1.Add(gx1, x1)                               // x1^3 + J*x1^2 + x1

	// Step 5: Compute x2 = -x1 - J/K = -x1 - J
	x2 := new(field.Element).Negate(x1)
	x2.Subtract(x2, JElement)

	// Step 6: Compute gx2 = x2^3 + J*x2^2 + x2
	gx2 := new(field.Element).Square(x2)
	gx2Temp := new(field.Element).Multiply(gx2, JElement)
	gx2.Multiply(gx2, x2)
	gx2.Add(gx2, gx2Temp)
	gx2.Add(gx2, x2)

	// Step 7: Check if gx1 is square using Legendre symbol
	e := chi25519(gx1)
	eBytes := e.Bytes()
	gx1IsSquare := 1 - int(eBytes[1]&1) // e==1 means square

	// Step 8: Select x based on whether gx1 is square
	var x *field.Element
	if gx1IsSquare == 1 {
		x = x1
	} else {
		x = x2
	}

	// Step 9: Compute y = sqrt(gx) (not needed for this rational map)
	// Step 10: s = x * K = x (since K=1)
	s := x

	// Step 11: Apply rational map from Montgomery (s,t) to Edwards (v,w)
	// For edwards25519: w = (s - 1) / (s + 1)
	// Note: We don't need t for this particular rational map

	// Compute w = (s - 1) / (s + 1)
	sMinusOne := new(field.Element).Subtract(s, one)
	sPlusOne := new(field.Element).Add(s, one)
	sPlusOneInv := new(field.Element).Invert(sPlusOne)
	w := new(field.Element).Multiply(sMinusOne, sPlusOneInv)

	// Edwards y-coordinate is w
	edwardsY := w.Bytes()

	// Decode as Edwards point and apply cofactor (per RFC 9380 encode_to_curve)
	point := &edwards25519.Point{}
	if _, err := point.SetBytes(edwardsY); err != nil {
		return nil, fmt.Errorf("elligator2: failed to decode edwards point (y=%x): %w", edwardsY, err)
	}

	point.MultByCofactor(point)
	return point.Bytes(), nil
}

// sqrtRatio computes sqrt(u/v) for field elements using the standard algorithm for p = 3 mod 4
func sqrtRatio(u, v *field.Element) *field.Element {
	// For p = 2^255 - 19 (which is 5 mod 8), we use a more complex algorithm
	// But for this use case, we can use chi25519 as a power function
	// sqrt(u) = u^((p+3)/8) for p = 5 mod 8
	// Actually, let's just use chi25519 which computes u^((p-1)/2)
	// and derive the square root from that

	// For simplicity with edwards25519, use the built-in power function
	// sqrt(u) can be computed as u^((p+3)/8) when p ≡ 5 (mod 8)
	// For edwards25519: p = 2^255 - 19 ≡ 5 (mod 8)

	// We'll compute this using repeated squaring via chi25519
	tv1 := new(field.Element).Set(u)
	tv1.Multiply(tv1, v)
	tv1 = chi25519(tv1)  // This gives us u^((p-1)/2)
	tv1.Multiply(tv1, u)

	return tv1
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

// hashPoints hashes five points to produce a scalar challenge
func hashPoints(P1, P2, P3, P4, P5 *edwards25519.Point) *edwards25519.Scalar {
	var input [2 + 32*5 + 1]byte // Added 1 byte for domain_separator_back

	input[0] = vrfSuite
	input[1] = 0x02  // challenge_generation_domain_separator_front
	copy(input[2:], P1.Bytes())
	copy(input[34:], P2.Bytes())
	copy(input[66:], P3.Bytes())
	copy(input[98:], P4.Bytes())
	copy(input[130:], P5.Bytes())
	input[162] = 0x00 // challenge_generation_domain_separator_back

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
	
	// cprime = hash_points(Y, H, Gamma, U, V)
	cprime := hashPoints(Y, H, Gamma, U, V)
	
	// Verify c == cprime (first 16 bytes)
	return subtle.ConstantTimeCompare(cBytes, cprime.Bytes()[:16]) == 1, nil
}

// proofToHash converts a VRF proof to its output hash
func proofToHash(pi []byte) ([]byte, error) {
	Gamma, _, _, err := decodeProof(pi)
	if err != nil {
		return nil, err
	}
	
	var hashInput [35]byte // Added 1 byte for domain_separator_back
	hashInput[0] = vrfSuite
	hashInput[1] = 0x03 // proof_to_hash_domain_separator_front

	// Gamma already has cofactor applied from hash-to-curve
	// Do NOT apply cofactor again here
	copy(hashInput[2:], Gamma.Bytes())
	hashInput[34] = 0x00 // proof_to_hash_domain_separator_back

	h := sha512.New()
	h.Write(hashInput[:])
	return h.Sum(nil), nil
}

// decodeProof decodes an 80-byte VRF proof
func decodeProof(pi []byte) (*edwards25519.Point, []byte, []byte, error) {
	if len(pi) != ProofSize {
		return nil, nil, nil, fmt.Errorf("proof must be %d bytes, got %d", ProofSize, len(pi))
	}
	
	// Gamma = pi[0:32]
	Gamma := &edwards25519.Point{}
	if _, err := Gamma.SetBytes(pi[:32]); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid Gamma point: %w", err)
	}
	
	// c = pi[32:48] (16 bytes)
	c := make([]byte, 16)
	copy(c, pi[32:48])
	
	// s = pi[48:80] (32 bytes)
	s := make([]byte, 32)
	copy(s, pi[48:80])
	
	return Gamma, c, s, nil
}