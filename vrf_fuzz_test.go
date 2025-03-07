// Copyright (C) 2019-2023 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package crypto

import (
	"bytes"
	"fmt"
	"testing"
)

// FuzzVRFCImplementation runs fuzzing on the C implementation of VRF
func FuzzVRFCImplementation(f *testing.F) {
	// Add diverse corpus seeds to guide the fuzzer toward interesting inputs
	// Standard test vectors
	f.Add([]byte(""), []byte("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
	f.Add([]byte("72"), []byte("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"))
	f.Add([]byte("hello world"), []byte("879a0117c5a21784c1842b94c2ebfe24396ec1dae09374a8eacc5971ed8dba2d"))
	
	// Edge cases: different message lengths with various seed patterns
	f.Add(bytes.Repeat([]byte{0}, 0), bytes.Repeat([]byte{0}, 32))   // Empty message, zero seed
	f.Add(bytes.Repeat([]byte{0}, 1), bytes.Repeat([]byte{0}, 32))   // Short message, zero seed
	f.Add(bytes.Repeat([]byte{0}, 1024), bytes.Repeat([]byte{0}, 32)) // Long message, zero seed
	f.Add([]byte("Short message"), bytes.Repeat([]byte{0xFF}, 32))    // Short message, max byte seed
	f.Add(bytes.Repeat([]byte{0xFF}, 10), bytes.Repeat([]byte{0xFF}, 32)) // Max byte message, max byte seed
	
	// Boundary cases and special values
	f.Add([]byte{0x00}, bytes.Repeat([]byte{0x01}, 32)) // Single null byte message
	f.Add([]byte{0xFF}, bytes.Repeat([]byte{0x80}, 32)) // Single 0xFF byte message
	
	// Messages likely to exercise hash function edge cases
	f.Add(bytes.Repeat([]byte{0x5A}, 64), bytes.Repeat([]byte{0x3C}, 32)) // Repeating pattern
	f.Add(bytes.Repeat([]byte("abc"), 20), bytes.Repeat([]byte{0xA5}, 32)) // Repeating string pattern
	
	// Fuzzing function
	f.Fuzz(func(t *testing.T, message []byte, seedBytes []byte) {
		// Ensure seed is 32 bytes
		if len(seedBytes) != 32 {
			return
		}
		
		// Create a seed array
		var seed [32]byte
		copy(seed[:], seedBytes)
		
		// Generate keypair
		pk, sk := VrfKeygenFromSeed(seed)
		
		// Try to generate a proof
		proof, ok := sk.proveBytes(message)
		if !ok {
			// Some seed/message combinations might not generate valid proofs, that's fine
			return
		}
		
		// Verify the proof
		verified, output := pk.verifyBytes(proof, message)
		if !verified {
			t.Fatalf("C implementation: Verification failed for valid proof")
		}
		
		// Ensure the proof is valid and can be re-verified
		reverified, output2 := pk.verifyBytes(proof, message)
		if !reverified {
			t.Fatalf("C implementation: Re-verification failed for valid proof")
		}
		
		// Outputs should be consistent
		if bytes.Compare(output[:], output2[:]) != 0 {
			t.Fatalf("C implementation: Output not consistent between verifications")
		}
	})
}

// FuzzVRFGoImplementation runs fuzzing on the Go implementation of VRF
func FuzzVRFGoImplementation(f *testing.F) {
	// Add diverse corpus seeds to guide the fuzzer toward interesting inputs
	// Standard test vectors
	f.Add([]byte(""), []byte("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
	f.Add([]byte("72"), []byte("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"))
	f.Add([]byte("hello world"), []byte("879a0117c5a21784c1842b94c2ebfe24396ec1dae09374a8eacc5971ed8dba2d"))
	
	// Edge cases: different message lengths with various seed patterns
	f.Add(bytes.Repeat([]byte{0}, 0), bytes.Repeat([]byte{0}, 32))   // Empty message, zero seed
	f.Add(bytes.Repeat([]byte{0}, 1), bytes.Repeat([]byte{0}, 32))   // Short message, zero seed
	f.Add(bytes.Repeat([]byte{0}, 1024), bytes.Repeat([]byte{0}, 32)) // Long message, zero seed
	f.Add([]byte("Short message"), bytes.Repeat([]byte{0xFF}, 32))    // Short message, max byte seed
	f.Add(bytes.Repeat([]byte{0xFF}, 10), bytes.Repeat([]byte{0xFF}, 32)) // Max byte message, max byte seed
	
	// Boundary cases and special values
	f.Add([]byte{0x00}, bytes.Repeat([]byte{0x01}, 32)) // Single null byte message
	f.Add([]byte{0xFF}, bytes.Repeat([]byte{0x80}, 32)) // Single 0xFF byte message
	
	// Messages likely to exercise hash function edge cases
	f.Add(bytes.Repeat([]byte{0x5A}, 64), bytes.Repeat([]byte{0x3C}, 32)) // Repeating pattern
	f.Add(bytes.Repeat([]byte("abc"), 20), bytes.Repeat([]byte{0xA5}, 32)) // Repeating string pattern
	
	// Fuzzing function
	f.Fuzz(func(t *testing.T, message []byte, seedBytes []byte) {
		// Ensure seed is 32 bytes
		if len(seedBytes) != 32 {
			return
		}
		
		// Create a seed array
		var seed [32]byte
		copy(seed[:], seedBytes)
		
		// Generate keypair
		pk, sk := VrfKeygenFromSeedGo(seed)
		
		// Try to generate a proof
		proof, ok := sk.proveBytesGo(message)
		if !ok {
			// Some seed/message combinations might not generate valid proofs, that's fine
			return
		}
		
		// Verify the proof
		verified, output := pk.verifyBytesGo(proof, message)
		if !verified {
			t.Fatalf("Go implementation: Verification failed for valid proof")
		}
		
		// Ensure the proof is valid and can be re-verified
		reverified, output2 := pk.verifyBytesGo(proof, message)
		if !reverified {
			t.Fatalf("Go implementation: Re-verification failed for valid proof")
		}
		
		// Outputs should be consistent
		if bytes.Compare(output[:], output2[:]) != 0 {
			t.Fatalf("Go implementation: Output not consistent between verifications")
		}
	})
}

// FuzzVRFImplementationComparison runs fuzzing to compare C and Go VRF implementations
func FuzzVRFImplementationComparison(f *testing.F) {
	// Add diverse corpus seeds to guide the fuzzer toward interesting inputs
	// Standard test vectors
	f.Add([]byte(""), []byte("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
	f.Add([]byte("72"), []byte("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"))
	f.Add([]byte("hello world"), []byte("879a0117c5a21784c1842b94c2ebfe24396ec1dae09374a8eacc5971ed8dba2d"))
	
	// Edge cases: different message lengths with various seed patterns
	f.Add(bytes.Repeat([]byte{0}, 0), bytes.Repeat([]byte{0}, 32))   // Empty message, zero seed
	f.Add(bytes.Repeat([]byte{0}, 1), bytes.Repeat([]byte{0}, 32))   // Short message, zero seed
	f.Add(bytes.Repeat([]byte{0}, 1024), bytes.Repeat([]byte{0}, 32)) // Long message, zero seed
	f.Add([]byte("Short message"), bytes.Repeat([]byte{0xFF}, 32))    // Short message, max byte seed
	f.Add(bytes.Repeat([]byte{0xFF}, 10), bytes.Repeat([]byte{0xFF}, 32)) // Max byte message, max byte seed
	
	// Boundary cases and special values
	f.Add([]byte{0x00}, bytes.Repeat([]byte{0x01}, 32)) // Single null byte message
	f.Add([]byte{0xFF}, bytes.Repeat([]byte{0x80}, 32)) // Single 0xFF byte message
	
	// Messages likely to exercise hash function edge cases
	f.Add(bytes.Repeat([]byte{0x5A}, 64), bytes.Repeat([]byte{0x3C}, 32)) // Repeating pattern
	f.Add(bytes.Repeat([]byte("abc"), 20), bytes.Repeat([]byte{0xA5}, 32)) // Repeating string pattern
	
	// Fuzzing function
	f.Fuzz(func(t *testing.T, message []byte, seedBytes []byte) {
		// Ensure seed is 32 bytes
		if len(seedBytes) != 32 {
			return
		}
		
		// Create a seed array
		var seed [32]byte
		copy(seed[:], seedBytes)
		
		// Generate keypairs from the same seed
		// Both implementations should generate identical keypairs from identical seeds
		pkC, skC := VrfKeygenFromSeed(seed)
		pkGo, skGo := VrfKeygenFromSeedGo(seed)
		
		// Keys should match between implementations
		if pkC != pkGo {
			t.Fatalf("Public keys don't match between C and Go implementations")
		}
		if fmt.Sprintf("%x", skC) != fmt.Sprintf("%x", skGo) {
			t.Fatalf("Private keys don't match between C and Go implementations")
		}
		
		// Try to generate proofs in both implementations
		proofC, okC := skC.proveBytes(message)
		proofGo, okGo := skGo.proveBytesGo(message)
		
		// Both should succeed or fail together for the same seed/message
		if okC != okGo {
			t.Fatalf("Proof generation success doesn't match: C=%v, Go=%v", okC, okGo)
		}
		
		// If we couldn't generate proofs, we're done
		if !okC {
			return
		}
		
		// Verify with both implementations
		// C verify
		cVerifiedC, cOutputC := pkC.verifyBytes(proofC, message)
		if !cVerifiedC {
			t.Fatalf("C verification failed for C proof")
		}
		
		// Go verify
		goVerifiedGo, goOutputGo := pkGo.verifyBytesGo(proofGo, message)
		if !goVerifiedGo {
			t.Fatalf("Go verification failed for Go proof")
		}
		
		// Cross-verify proofs
		cVerifiedGo, cOutputGo := pkC.verifyBytes(proofGo, message)
		if !cVerifiedGo {
			t.Fatalf("C verification failed for Go proof")
		}
		
		goVerifiedC, goOutputC := pkGo.verifyBytesGo(proofC, message)
		if !goVerifiedC {
			t.Fatalf("Go verification failed for C proof")
		}
		
		// For a given pk and message, outputs should match, even if proofs differ
		if bytes.Compare(cOutputC[:], goOutputGo[:]) != 0 {
			t.Fatalf("C and Go outputs don't match: %x vs %x", cOutputC, goOutputGo)
		}
		
		if bytes.Compare(cOutputC[:], cOutputGo[:]) != 0 {
			t.Fatalf("C output for C proof doesn't match C output for Go proof: %x vs %x", cOutputC, cOutputGo)
		}
		
		if bytes.Compare(goOutputGo[:], goOutputC[:]) != 0 {
			t.Fatalf("Go output for Go proof doesn't match Go output for C proof: %x vs %x", goOutputGo, goOutputC)
		}
	})
}

// FuzzVRFPropertyVerification explicitly tests the fundamental property that
// verification of a proof generated with a key always succeeds for that key
func FuzzVRFPropertyVerification(f *testing.F) {
	// Add diverse corpus seeds for property testing
	f.Add([]byte(""), []byte("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
	f.Add([]byte("Property testing"), bytes.Repeat([]byte{0x55}, 32))
	f.Add(bytes.Repeat([]byte{0x42}, 100), bytes.Repeat([]byte{0x42}, 32))
	
	f.Fuzz(func(t *testing.T, message []byte, seedBytes []byte) {
		if len(seedBytes) != 32 {
			return
		}
		
		var seed [32]byte
		copy(seed[:], seedBytes)
		
		// Test the C implementation
		pkC, skC := VrfKeygenFromSeed(seed)
		proofC, okC := skC.proveBytes(message)
		if !okC {
			return // Proof generation might fail, that's expected for some inputs
		}
		
		verifiedC, _ := pkC.verifyBytes(proofC, message)
		if !verifiedC {
			t.Fatalf("Property violation (C): Verification failed for proof generated with the same key and message")
		}
		
		// Test the Go implementation with the same inputs
		pkGo, skGo := VrfKeygenFromSeedGo(seed)
		proofGo, okGo := skGo.proveBytesGo(message)
		if !okGo {
			return
		}
		
		verifiedGo, _ := pkGo.verifyBytesGo(proofGo, message)
		if !verifiedGo {
			t.Fatalf("Property violation (Go): Verification failed for proof generated with the same key and message")
		}
	})
}

// FuzzVRFProofModification tests that modifying proofs invalidates them,
// ensuring the implementation properly detects tampered proofs
func FuzzVRFProofModification(f *testing.F) {
	// Add test vectors
	f.Add([]byte("Message to sign"), []byte("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"), byte(0))
	f.Add([]byte("Another message"), bytes.Repeat([]byte{0x77}, 32), byte(42))
	
	f.Fuzz(func(t *testing.T, message []byte, seedBytes []byte, modifyByte byte) {
		if len(seedBytes) != 32 {
			return
		}
		
		var seed [32]byte
		copy(seed[:], seedBytes)
		
		// Generate keypairs and proofs
		pk, sk := VrfKeygenFromSeed(seed)
		proof, ok := sk.proveBytes(message)
		if !ok {
			return
		}
		
		// First verify that the unmodified proof is valid
		verified, _ := pk.verifyBytes(proof, message)
		if !verified {
			t.Fatalf("Original proof should be valid")
		}
		
		// Now modify the proof by changing a single byte
		// Choose modification position based on modifyByte to explore different positions
		modifyPos := int(modifyByte) % len(proof)
		modifiedProof := proof
		modifiedProof[modifyPos] ^= 0x01 // Flip one bit in the chosen byte
		
		// A modified proof should fail verification
		modVerified, _ := pk.verifyBytes(modifiedProof, message)
		if modVerified {
			t.Fatalf("Modified proof was incorrectly verified as valid (modified position %d)", modifyPos)
		}
		
		// Test the same with Go implementation
		pkGo, skGo := VrfKeygenFromSeedGo(seed)
		proofGo, okGo := skGo.proveBytesGo(message)
		if !okGo {
			return
		}
		
		verifiedGo, _ := pkGo.verifyBytesGo(proofGo, message)
		if !verifiedGo {
			t.Fatalf("Original Go proof should be valid")
		}
		
		modifiedProofGo := proofGo
		modifiedProofGo[modifyPos] ^= 0x01
		
		modVerifiedGo, _ := pkGo.verifyBytesGo(modifiedProofGo, message)
		if modVerifiedGo {
			t.Fatalf("Modified Go proof was incorrectly verified as valid")
		}
	})
}