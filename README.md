# VRF

Package vrf implements the ECVRF-EDWARDS25519-SHA512-ELL2 verifiable random
function (suite 0x04) from draft-irtf-cfrg-vrf-03.

This is the suite used by Algorand's consensus layer. Proofs and outputs are
byte-identical to Algorand's libsodium fork, checked against verify vectors
taken from Algorand's implementation (`vrf_parity_test.go`). RFC 9381 kept the
same suite byte (0x04) but changed hash-to-curve and challenge construction
incompatibly, so it ships as a separate package.

## Packages

- `github.com/tmc/vrf`: draft-03 implementation (Algorand-compatible).
- `github.com/tmc/vrf/draft03`: explicit import path for the same draft-03 implementation.
- `github.com/tmc/vrf/rfc9381`: RFC 9381 implementation.

## Usage

```go
import "github.com/tmc/vrf"

// Generate a key pair from randomness.
pk, sk, err := vrf.GenerateKey(rand.Reader)

// Or derive a private key from a 32-byte seed.
sk = vrf.NewKeyFromSeed(seed)
pk = sk.Public().(vrf.PublicKey)

// Create a proof.
proof, err := sk.Prove(message)

// Verify and get the output.
output, err := vrf.Verify(pk, message, proof)
```

For new code that must make the suite explicit, import
`github.com/tmc/vrf/draft03` or `github.com/tmc/vrf/rfc9381`. Each package uses
distinct named proof and key types, so a draft-03 proof cannot be passed to the
RFC 9381 verifier by accident.

See package documentation for details.
