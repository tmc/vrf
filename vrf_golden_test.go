package crypto

import (
	"encoding/json"
	"flag"
	"fmt"
	mathrand "math/rand"
	"os"
	"path/filepath"
	"testing"
)

var (
	updateGolden = flag.Bool("update", false, "Update golden files instead of verifying against them")
)

// VRFTestVector represents a single test vector for VRF verification
type VRFTestVector struct {
	PublicKey   string `json:"public_key"`
	Message     string `json:"message"`
	GoProof     string `json:"go_proof"`
	CProof      string `json:"c_proof"`
	GoVerifyOut string `json:"go_verify_out"`
	CVerifyOut  string `json:"c_verify_out"`
}

// VRFGoldenTests represents a collection of test vectors for VRF
type VRFGoldenTests struct {
	Vectors []VRFTestVector `json:"vectors"`
}

// TestVRFGoldenFiles tests that the C and Go VRF implementations match stored golden files
func TestVRFGoldenFiles(t *testing.T) {
	// Always parse flags in tests
	if !flag.Parsed() {
		flag.Parse()
	}

	// Generate golden file data if it doesn't exist or if update flag is set
	goldenPath := filepath.Join("testdata", "vrf_vectors.json")

	// If updating or file doesn't exist, generate new test vectors
	if *updateGolden || !fileExists(goldenPath) {
		generateAndSaveGoldenFile(t, goldenPath)
		t.Logf("Generated new golden file: %s", goldenPath)
		return
	}

	// Load and verify against golden file
	goldenData, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("Failed to read golden file: %v", err)
	}

	var goldenTests VRFGoldenTests
	err = json.Unmarshal(goldenData, &goldenTests)
	if err != nil {
		t.Fatalf("Failed to unmarshal golden file data: %v", err)
	}

	// Verify each test vector
	for i, vector := range goldenTests.Vectors {
		t.Run(fmt.Sprintf("Vector_%d", i), func(t *testing.T) {
			// Convert hex strings to byte arrays
			pubKeyBytes := hexToBytes(t, vector.PublicKey)
			msgBytes := hexToBytes(t, vector.Message)
			goProofBytes := hexToBytes(t, vector.GoProof)
			cProofBytes := hexToBytes(t, vector.CProof)
			goVerifyOutBytes := hexToBytes(t, vector.GoVerifyOut)
			cVerifyOutBytes := hexToBytes(t, vector.CVerifyOut)

			// Check that stored values match
			checkLength(t, pubKeyBytes, 32, "Public key length mismatch")
			checkLength(t, goProofBytes, 80, "Go proof length mismatch")
			checkLength(t, cProofBytes, 80, "C proof length mismatch")
			checkLength(t, goVerifyOutBytes, 64, "Go verify output length mismatch")
			checkLength(t, cVerifyOutBytes, 64, "C verify output length mismatch")

			// Convert to proper types
			var pk VrfPubkey
			copy(pk[:], pubKeyBytes)

			var goProof VrfProof
			copy(goProof[:], goProofBytes)

			var cProof VrfProof
			copy(cProof[:], cProofBytes)

			var goOutput VrfOutput
			copy(goOutput[:], goVerifyOutBytes)

			var cOutput VrfOutput
			copy(cOutput[:], cVerifyOutBytes)

			// Verify that the proofs can be verified with the corresponding outputs
			goOk, goOut := pk.verifyBytesGo(goProof, msgBytes)
			if !goOk {
				t.Errorf("Go verification failed")
			}
			if goOutput != goOut {
				t.Errorf("Go outputs don't match: expected %x, got %x", goOutput, goOut)
			}

			cOk, cOut := pk.verifyBytes(cProof, msgBytes)
			if !cOk {
				t.Errorf("C verification failed")
			}
			if cOutput != cOut {
				t.Errorf("C outputs don't match: expected %x, got %x", cOutput, cOut)
			}
		})
	}
}

// Generate and save a golden file
func generateAndSaveGoldenFile(t *testing.T, path string) {
	// Number of test vectors to generate
	const n = 10
	randSource := mathrand.New(mathrand.NewSource(42)) // Fixed seed for reproducibility

	pks := make([]VrfPubkey, n)
	sks := make([]VrfPrivkey, n)
	msgs := make([][]byte, n)
	goProofs := make([]VrfProof, n)
	cProofs := make([]VrfProof, n)
	goOuts := make([]VrfOutput, n)
	cOuts := make([]VrfOutput, n)

	// Generate keys and messages
	for i := 0; i < n; i++ {
		pks[i], sks[i] = VrfKeygen()
		msgs[i] = make([]byte, 32)
		_, err := randSource.Read(msgs[i])
		if err != nil {
			t.Fatalf("Failed to generate random message: %v", err)
		}
	}

	// Generate proofs and verify outputs
	for i := 0; i < n; i++ {
		var ok bool
		// C implementation
		cProofs[i], ok = sks[i].proveBytes(msgs[i])
		if !ok {
			t.Fatalf("C proof generation failed for vector %d", i)
		}
		ok, cOuts[i] = pks[i].verifyBytes(cProofs[i], msgs[i])
		if !ok {
			t.Fatalf("C verification failed for vector %d", i)
		}

		// Go implementation
		goProofs[i], ok = sks[i].proveBytesGo(msgs[i])
		if !ok {
			t.Fatalf("Go proof generation failed for vector %d", i)
		}
		ok, goOuts[i] = pks[i].verifyBytesGo(goProofs[i], msgs[i])
		if !ok {
			t.Fatalf("Go verification failed for vector %d", i)
		}
	}

	// Create test vectors
	var goldenTests VRFGoldenTests
	for i := 0; i < n; i++ {
		vector := VRFTestVector{
			PublicKey:   bytesToHex(pks[i][:]),
			Message:     bytesToHex(msgs[i]),
			GoProof:     bytesToHex(goProofs[i][:]),
			CProof:      bytesToHex(cProofs[i][:]),
			GoVerifyOut: bytesToHex(goOuts[i][:]),
			CVerifyOut:  bytesToHex(cOuts[i][:]),
		}
		goldenTests.Vectors = append(goldenTests.Vectors, vector)
	}

	// Save to file
	data, err := json.MarshalIndent(goldenTests, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal test vectors: %v", err)
	}

	err = os.WriteFile(path, data, 0644)
	if err != nil {
		t.Fatalf("Failed to write golden file: %v", err)
	}
}

// Helper functions
func bytesToHex(data []byte) string {
	return fmt.Sprintf("%x", data)
}

func hexToBytes(t *testing.T, hexStr string) []byte {
	// Create a buffer with the appropriate size
	rawBytes := make([]byte, len(hexStr)/2)

	// Convert from hex
	_, err := fmt.Sscanf(hexStr, "%x", &rawBytes)
	if err != nil {
		t.Fatalf("Failed to convert hex string to bytes: %v", err)
	}

	return rawBytes
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func checkLength(t *testing.T, data []byte, expected int, message string) {
	if len(data) != expected {
		t.Errorf("%s: expected length %d, got %d", message, expected, len(data))
	}
}

// TestVRFImplementationConsistency tests that the C and Go implementations are consistent
func TestVRFImplementationConsistency(t *testing.T) {
	// Number of test vectors to generate and check
	const n = 50
	randSource := mathrand.New(mathrand.NewSource(42)) // Fixed seed for reproducibility

	pks := make([]VrfPubkey, n)
	sks := make([]VrfPrivkey, n)
	msgs := make([][]byte, n)

	// Generate keys and messages
	for i := 0; i < n; i++ {
		pks[i], sks[i] = VrfKeygen()
		msgs[i] = make([]byte, 32)
		_, err := randSource.Read(msgs[i])
		if err != nil {
			t.Fatalf("Failed to generate random message: %v", err)
		}
	}

	// Compare proofs and verification for each test vector
	for i := 0; i < n; i++ {
		// Generate proofs
		cProof, cOk := sks[i].proveBytes(msgs[i])
		goProof, goOk := sks[i].proveBytesGo(msgs[i])

		// While proofs may be different, both should succeed
		if !cOk {
			t.Errorf("C proof generation failed for message %d", i)
		}
		if !goOk {
			t.Errorf("Go proof generation failed for message %d", i)
		}

		// Verify proofs
		cVerifyOk, cOut := pks[i].verifyBytes(cProof, msgs[i])
		goVerifyOk, goOut := pks[i].verifyBytesGo(goProof, msgs[i])

		// Both verifications should succeed
		if !cVerifyOk {
			t.Errorf("C verification failed for message %d", i)
		}
		if !goVerifyOk {
			t.Errorf("Go verification failed for message %d", i)
		}

		// Cross-verify proofs
		crossGoOk, crossGoOut := pks[i].verifyBytesGo(cProof, msgs[i])
		crossCOk, crossCOut := pks[i].verifyBytes(goProof, msgs[i])

		// Cross verification should succeed
		if !crossGoOk {
			t.Errorf("Cross Go verification failed for message %d", i)
		}
		if !crossCOk {
			t.Errorf("Cross C verification failed for message %d", i)
		}

		// For a given pk and message, outputs should match, even if proofs differ
		if cOut != goOut {
			t.Errorf("C and Go outputs don't match for message %d", i)
		}
		if cOut != crossGoOut {
			t.Errorf("C and Cross Go outputs don't match for message %d", i)
		}
		if goOut != crossCOut {
			t.Errorf("Go and Cross C outputs don't match for message %d", i)
		}
	}
}
