package rfc9381

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"filippo.io/edwards25519"
)

func TestRFC9381Vectors(t *testing.T) {
	for _, v := range rfcVectors {
		t.Run(v.name, func(t *testing.T) {
			seed := decodeHex(t, v.seed)
			wantPK := decodeHex(t, v.publicKey)
			msg := decodeHex(t, v.message)
			wantProof := decodeHex(t, v.proof)
			wantOutput := decodeHex(t, v.output)

			priv := NewKeyFromSeed(seed)
			pub := priv.Public().(PublicKey)
			if !bytes.Equal(pub[:], wantPK) {
				t.Fatalf("public key = %x, want %x", pub[:], wantPK)
			}

			proof, err := priv.Prove(msg)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(proof[:], wantProof) {
				t.Fatalf("proof = %x, want %x", proof[:], wantProof)
			}

			output, err := Verify(pub, msg, proof)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(output[:], wantOutput) {
				t.Fatalf("output = %x, want %x", output[:], wantOutput)
			}

			parsedPub, err := ParsePublicKey(wantPK)
			if err != nil {
				t.Fatal(err)
			}
			parsedProof, err := ParseProof(wantProof)
			if err != nil {
				t.Fatal(err)
			}
			output, err = parsedPub.Verify(parsedProof, msg)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(output[:], wantOutput) {
				t.Fatalf("parsed output = %x, want %x", output[:], wantOutput)
			}
		})
	}
}

func TestConstructorsAndSentinels(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, SeedSize)
	pub, priv, err := GenerateKey(bytes.NewReader(seed))
	if err != nil {
		t.Fatal(err)
	}
	wantPriv := NewKeyFromSeed(seed)
	wantPub := wantPriv.Public().(PublicKey)
	if !pub.Equal(wantPub) || !priv.Equal(wantPriv) {
		t.Fatal("GenerateKey returned unexpected key")
	}
	if !pub.Equal(crypto.PublicKey(wantPub)) || !priv.Equal(crypto.PrivateKey(wantPriv)) {
		t.Fatal("Equal rejected equal key")
	}
	if !bytes.Equal(priv.Seed(), seed) {
		t.Fatal("Seed returned unexpected value")
	}

	_, _, err = GenerateKey(bytes.NewReader(seed[:SeedSize-1]))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("GenerateKey error = %v, want %v", err, io.ErrUnexpectedEOF)
	}
	if _, err := ParsePublicKey(pub[:PublicKeySize-1]); !errors.Is(err, ErrInvalidPublicKey) {
		t.Fatalf("ParsePublicKey error = %v, want %v", err, ErrInvalidPublicKey)
	}
	invalidPub, err := ParsePublicKey(decodeHex(t, "0200000000000000000000000000000000000000000000000000000000000000"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(invalidPub, []byte("message"), Proof{}); !errors.Is(err, ErrInvalidPublicKey) {
		t.Fatalf("invalid public key error = %v, want %v", err, ErrInvalidPublicKey)
	}

	proof, err := priv.Prove([]byte("message"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseProof(proof[:ProofSize-1]); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("ParseProof error = %v, want %v", err, ErrInvalidProof)
	}
	invalidProof, err := ParseProof(bytes.Repeat([]byte{0xff}, ProofSize))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(pub, []byte("message"), invalidProof); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("invalid proof error = %v, want %v", err, ErrInvalidProof)
	}
	if _, err := Verify(pub, []byte("wrong"), proof); !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("Verify error = %v, want %v", err, ErrVerifyFailed)
	}

	var small PublicKey
	copy(small[:], []byte{1})
	if _, err := Verify(small, []byte("message"), proof); !errors.Is(err, ErrSmallOrderPoint) {
		t.Fatalf("small-order error = %v, want %v", err, ErrSmallOrderPoint)
	}

	var zero PrivateKey
	if _, err := zero.Prove([]byte("message")); !errors.Is(err, ErrSmallOrderPoint) {
		t.Fatalf("zero private key error = %v, want %v", err, ErrSmallOrderPoint)
	}
}

func FuzzVerify(f *testing.F) {
	for _, v := range rfcVectors {
		f.Add(decodeHex(f, v.publicKey), decodeHex(f, v.proof), decodeHex(f, v.message))
	}
	f.Fuzz(func(t *testing.T, publicKey, proof, message []byte) {
		pk, err := ParsePublicKey(publicKey)
		if err != nil {
			return
		}
		pi, err := ParseProof(proof)
		if err != nil {
			return
		}
		Verify(pk, message, pi)
	})
}

func TestVerificationDoubleScalarOperation(t *testing.T) {
	for _, v := range rfcVectors {
		t.Run(v.name, func(t *testing.T) {
			seed := decodeHex(t, v.seed)
			proof := decodeHex(t, v.proof)
			priv := NewKeyFromSeed(seed)
			pub := priv.Public().(PublicKey)

			Y := new(edwards25519.Point)
			if _, err := Y.SetBytes(pub[:]); err != nil {
				t.Fatal(err)
			}
			var Gamma edwards25519.Point
			var s edwards25519.Scalar
			cBytes, err := decodeProof(&Gamma, &s, proof)
			if err != nil {
				t.Fatal(err)
			}
			var c edwards25519.Scalar
			scalarFromTruncated(&c, cBytes)

			wantU := new(edwards25519.Point).Subtract(
				new(edwards25519.Point).ScalarBaseMult(&s),
				new(edwards25519.Point).ScalarMult(&c, Y),
			)
			negC := new(edwards25519.Scalar).Negate(&c)
			gotU := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(negC, Y, &s)
			if gotU.Equal(wantU) != 1 {
				t.Fatal("s*B - c*Y equation mismatch")
			}
		})
	}
}

func TestProofToHashValidation(t *testing.T) {
	proof := decodeHex(t, rfcVectors[0].proof)
	want := decodeHex(t, rfcVectors[0].output)
	got, err := proofToHash(proof)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("proofToHash = %x, want %x", got, want)
	}

	invalid := bytes.Repeat([]byte{0xff}, ProofSize)
	if _, err := proofToHash(invalid); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("proofToHash error = %v, want %v", err, ErrInvalidProof)
	}
}

// TestVerifyRejectsUndecodableGamma reaches the Gamma rejection in decodeProof
// through the public Verify. The encoding below is y = 2, which is not on the
// curve: (y²-1)/(dy²+1) is a nonsquare, so no x exists and decoding fails for
// every key, which keeps the case independent of the key material.
//
// The value is written as the non-canonical y = p+2 to match the draft03 test.
// That non-canonicality is not what makes it fail: edwards25519 reduces y
// before use, so p+1 and p+3 decode fine and the canonical y = 2 fails
// identically.
func TestVerifyRejectsUndecodableGamma(t *testing.T) {
	seed := decodeHex(t, rfcVectors[0].seed)
	message := decodeHex(t, rfcVectors[0].message)

	priv := NewKeyFromSeed(seed)
	pub := priv.Public().(PublicKey)
	proof, err := priv.Prove(message)
	if err != nil {
		t.Fatal(err)
	}

	badGamma := proof
	copy(badGamma[:32], decodeHex(t, "efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"))

	if _, err := pub.Verify(badGamma, message); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("Verify(undecodable Gamma) error = %v, want %v", err, ErrInvalidProof)
	}
}

func TestExpandMessageXMDSHA512(t *testing.T) {
	dst := []byte("QUUX-V01-CS02-with-expander-SHA512-256")
	want := decodeHex(t, "0da749f12fbe5483eb066a5f595055679b976e93abe9be6f0f6318bce7aca8dc")
	got := expandMessageXMD([]byte("abc"), dst, len(want))
	if !bytes.Equal(got, want) {
		t.Fatalf("expandMessageXMD = %x, want %x", got, want)
	}
}

// TestOutputPrefixUint64 checks the big-endian interpretation against a
// hardcoded value rather than against binary.BigEndian, which would restate
// the implementation and pass just as well if both switched to little-endian.
func TestOutputPrefixUint64(t *testing.T) {
	var out Output
	copy(out[:], decodeHex(t, "0123456789abcdef"+
		"00000000000000000000000000000000000000000000000000000000"))
	if got, want := out.PrefixUint64(), uint64(0x0123456789abcdef); got != want {
		t.Errorf("PrefixUint64 = %#016x, want %#016x", got, want)
	}

	// The first RFC 9381 Appendix B.4 vector, so the expected value is fixed
	// by the specification and not by this implementation.
	full := decodeHex(t, rfcVectors[0].output)
	copy(out[:], full)
	if got, want := out.PrefixUint64(), uint64(0x9d574bf9b8302ec0); got != want {
		t.Errorf("PrefixUint64(%s) = %#016x, want %#016x", rfcVectors[0].name, got, want)
	}

	// Only the first 8 bytes may contribute.
	var tail Output
	copy(tail[:], full)
	for i := 8; i < len(tail); i++ {
		tail[i] ^= 0xff
	}
	if got, want := tail.PrefixUint64(), out.PrefixUint64(); got != want {
		t.Errorf("PrefixUint64 changed with the tail: %#016x, want %#016x", got, want)
	}
}

// TestExpandMessageXMDMultiBlock checks expandMessageXMD against the
// expand_message_xmd(SHA-512) vectors in RFC 9380, Appendix K.3. Both
// callers in this package request 48 bytes, so ell is always 1 and the
// b_0 XOR b_(i-1) chain never runs. These vectors request 128 bytes,
// which sets ell to 2 and covers it.
//
// expandMessageXMD is the oracle TestExpandMessageXMD48 compares against,
// so it needs vectors of its own rather than a differential check alone.
func TestExpandMessageXMDMultiBlock(t *testing.T) {
	dst := []byte("QUUX-V01-CS02-with-expander-SHA512-256")
	for _, v := range []struct {
		msg  string
		want string
	}{
		{
			msg: "",
			want: "41b037d1734a5f8df225dd8c7de38f851efdb45c372887be655212d07251b921" +
				"b052b62eaed99b46f72f2ef4cc96bfaf254ebbbec091e1a3b9e4fb5e5b619d2e" +
				"0c5414800a1d882b62bb5cd1778f098b8eb6cb399d5d9d18f5d5842cf5d13d7e" +
				"b00a7cff859b605da678b318bd0e65ebff70bec88c753b159a805d2c89c55961",
		},
		{
			msg: "abc",
			want: "7f1dddd13c08b543f2e2037b14cefb255b44c83cc397c1786d975653e36a6b11" +
				"bdd7732d8b38adb4a0edc26a0cef4bb45217135456e58fbca1703cd6032cb134" +
				"7ee720b87972d63fbf232587043ed2901bce7f22610c0419751c065922b48843" +
				"1851041310ad659e4b23520e1772ab29dcdeb2002222a363f0c2b1c972b3efe1",
		},
		{
			msg: "abcdef0123456789",
			want: "3f721f208e6199fe903545abc26c837ce59ac6fa45733f1baaf0222f8b7acb04" +
				"24814fcb5eecf6c1d38f06e9d0a6ccfbf85ae612ab8735dfdf9ce84c372a77c8" +
				"f9e1c1e952c3a61b7567dd0693016af51d2745822663d0c2367e3f4f0bed827f" +
				"eecc2aaf98c949b5ed0d35c3f1023d64ad1407924288d366ea159f46287e61ac",
		},
	} {
		t.Run(v.msg, func(t *testing.T) {
			want := decodeHex(t, v.want)
			got := expandMessageXMD([]byte(v.msg), dst, len(want))
			if !bytes.Equal(got, want) {
				t.Errorf("expandMessageXMD(%q) = %x, want %x", v.msg, got, want)
			}
		})
	}
}

func TestExpandMessageXMD48(t *testing.T) {
	for _, size := range []int{0, 3, 64, 1024, 4096} {
		msg := bytes.Repeat([]byte{0x5a}, size)
		want := expandMessageXMD(msg, hashToCurveDST, 48)
		for _, split := range []int{0, len(msg) / 2, len(msg)} {
			got := expandMessageXMD48(msg[:split], msg[split:])
			if !bytes.Equal(got[:], want) {
				t.Fatalf("size %d, split %d: expandMessageXMD48 = %x, want %x", size, split, got, want)
			}
		}
	}
}

var rfcVectors = []struct {
	name      string
	seed      string
	publicKey string
	message   string
	proof     string
	output    string
}{
	{
		name:      "example_19",
		seed:      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
		publicKey: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
		message:   "",
		proof:     "7d9c633ffeee27349264cf5c667579fc583b4bda63ab71d001f89c10003ab46f14adf9a3cd8b8412d9038531e865c341cafa73589b023d14311c331a9ad15ff2fb37831e00f0acaa6d73bc9997b06501",
		output:    "9d574bf9b8302ec0fc1e21c3ec5368269527b87b462ce36dab2d14ccf80c53cccf6758f058c5b1c856b116388152bbe509ee3b9ecfe63d93c3b4346c1fbc6c54",
	},
	{
		name:      "example_20",
		seed:      "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
		publicKey: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
		message:   "72",
		proof:     "47b327393ff2dd81336f8a2ef10339112401253b3c714eeda879f12c509072ef055b48372bb82efbdce8e10c8cb9a2f9d60e93908f93df1623ad78a86a028d6bc064dbfc75a6a57379ef855dc6733801",
		output:    "38561d6b77b71d30eb97a062168ae12b667ce5c28caccdf76bc88e093e4635987cd96814ce55b4689b3dd2947f80e59aac7b7675f8083865b46c89b2ce9cc735",
	},
	{
		name:      "example_21",
		seed:      "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
		publicKey: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
		message:   "af82",
		proof:     "926e895d308f5e328e7aa159c06eddbe56d06846abf5d98c2512235eaa57fdce35b46edfc655bc828d44ad09d1150f31374e7ef73027e14760d42e77341fe05467bb286cc2c9d7fde29120a0b2320d04",
		output:    "121b7f9b9aaaa29099fc04a94ba52784d44eac976dd1a3cca458733be5cd090a7b5fbd148444f17f8daf1fb55cb04b1ae85a626e30a54b4b0f8abf4a43314a58",
	},
}

func decodeHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
