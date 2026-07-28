# VRF

Package vrf implements the ECVRF-EDWARDS25519-SHA512-ELL2 verifiable random
function (suite 0x04) from RFC 9381, the final published standard.

The root package is the default entry point and re-exports
`github.com/tmc/vrf/rfc9381`. RFC 9381 kept the suite byte (0x04) used by the
earlier draft-irtf-cfrg-vrf-03 but changed hash-to-curve and challenge
construction incompatibly, so the draft-03 suite ships as a separate package.

## Packages

- `github.com/tmc/vrf`: RFC 9381 implementation (default; re-exports `rfc9381`).
- `github.com/tmc/vrf/rfc9381`: RFC 9381 implementation.
  Tests cover RFC 9381 Appendix B.4 and custom vectors from an independent
  Rust implementation pinned in `rfc9381/interop_test.go`.
- `github.com/tmc/vrf/draft03`: draft-03 implementation, used by Algorand's
  consensus layer. Tests compare proofs and outputs with vectors captured from
  Algorand's implementation; they establish agreement for those cases, not
  general interoperability (`draft03/vrf_parity_test.go`).

## Usage

```go
import "github.com/tmc/vrf"

// Generate a key pair from randomness.
pk, sk, err := vrf.GenerateKey(rand.Reader)

// Or derive a private key from a 32-byte seed.
sk = vrf.NewKeyFromSeed(seed)
pk = sk.PublicKey()

// Create a proof.
proof, err := sk.Prove(message)

// Verify and get the output.
output, err := vrf.Verify(pk, message, proof)
```

For Algorand-compatible proofs, import `github.com/tmc/vrf/draft03`. Its proof
and key types are distinct from the RFC 9381 types, so a draft-03 proof cannot
be passed to an RFC 9381 verifier by accident.

See package documentation for details.
