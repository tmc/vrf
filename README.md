# VRF

Package vrf implements ECVRF-EDWARDS25519-SHA512-ELL2 (suite 0x04).

This follows draft-irtf-cfrg-vrf-03 to match Algorand's consensus layer.
RFC 9381 final changed hash-to-curve and transcript details, breaking
compatibility. Both suites are available as distinct packages.

## Packages

- `github.com/tmc/vrf`: Algorand-compatible draft-03 implementation.
- `github.com/tmc/vrf/algorand`: explicit import path for the same Algorand-compatible implementation.
- `github.com/tmc/vrf/rfc9381`: RFC 9381 implementation.

## Usage

```go
import "github.com/tmc/vrf"

// Generate key pair from randomness
pk, sk, err := vrf.GenerateKey(rand.Reader)

// Or derive a private key from a 32-byte seed
sk = vrf.NewKeyFromSeed(seed)
pk = sk.Public().(vrf.PublicKey)

// Create proof
proof, err := sk.Prove(message)

// Verify and get output
output, err := vrf.Verify(pk, message, proof)
```

For new code that must make the suite explicit, import `github.com/tmc/vrf/algorand`
or `github.com/tmc/vrf/rfc9381`. The RFC 9381 package uses distinct named proof
and key types, so Algorand draft-03 proofs cannot be passed to the RFC 9381
verifier by accident.

See package documentation for details.
