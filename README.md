# vrf

[![Go Reference](https://pkg.go.dev/badge/github.com/tmc/vrf.svg)](https://pkg.go.dev/github.com/tmc/vrf)

Package vrf implements the ECVRF-EDWARDS25519-SHA512-ELL2 verifiable random
function from RFC 9381.

RFC 9381 kept the suite byte 0x04 of the earlier draft-irtf-cfrg-vrf-03 but
changed hash-to-curve and challenge construction, so the two are not
interoperable. The draft-03 suite, used by Algorand and Cardano, is a
separate package with its own key and proof types.

- `github.com/tmc/vrf`: RFC 9381; re-exports `rfc9381`.
- `github.com/tmc/vrf/rfc9381`: RFC 9381.
- `github.com/tmc/vrf/draft03`: draft-irtf-cfrg-vrf-03.

```go
pub, priv, err := vrf.GenerateKey(rand.Reader)
if err != nil {
	log.Fatal(err)
}
proof, err := priv.Prove(message)
if err != nil {
	log.Fatal(err)
}
output, err := vrf.Verify(pub, message, proof)
```

Requires Go 1.24 or later. BSD 3-Clause license.
