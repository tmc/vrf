package algorand

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestVerifyAlgorandVector(t *testing.T) {
	pub := mustDecodeHex(t, "11025f38a47ba4aa9859c7f65f42bd849dda8b1b897e5260b97da825a1c99e2a")
	msg := mustDecodeHex(t, "538c7f96b164bf1b97bb9f4bb472e89f5b1484f25209c9d9343e92ba09dd9d52")
	proofBytes := mustDecodeHex(t, "ad3095f967bc1cf254c883ea37a0a2126da8ad2585106507bdb6853579cb82eeb1236e94c08518b66d282d5ca65f5e01dc5c73167f773696f75b0f84fe5f2290d9ea39f53e398d44c72d5be56e508b03")
	want := mustDecodeHex(t, "e6f5aa3938f5415592cfc0496c0fe4e3c29e89f8e68eacc84b6fc342d90dd5de9b31a45b79ba57321eab814f1bb704f8c0b3396dd1bbcb857f3603e390c75575")

	pk, err := ParsePublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ParseProof(proofBytes)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Verify(pk, msg, proof)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out[:], want) {
		t.Fatalf("Verify output = %x, want %x", out[:], want)
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
