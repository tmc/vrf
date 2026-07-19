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
			_, cBytes, s, err := decodeProof(proof)
			if err != nil {
				t.Fatal(err)
			}
			c := scalarFromTruncated(cBytes)

			wantU := new(edwards25519.Point).Subtract(
				new(edwards25519.Point).ScalarBaseMult(s),
				new(edwards25519.Point).ScalarMult(c, Y),
			)
			negC := new(edwards25519.Scalar).Negate(c)
			gotU := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(negC, Y, s)
			if gotU.Equal(wantU) != 1 {
				t.Fatal("s*B - c*Y equation mismatch")
			}
		})
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

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
