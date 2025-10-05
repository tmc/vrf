# VRF

Package vrf implements ECVRF-EDWARDS25519-SHA512-ELL2 (suite 0x04).

This follows draft-irtf-cfrg-vrf-03 to match Algorand's consensus layer.
RFC 9381 final changed hash-to-curve (draft-07+), breaking compatibility.
Algorand cannot upgrade due to blockchain immutability.

## Usage

```go
import "github.com/tmc/vrf"

// Generate key pair from seed
pk, sk := vrf.Keygen(seed)

// Create proof
proof, err := sk.Prove(message)

// Verify and get output
output, err := pk.Verify(proof, message)
```

See package documentation for details.
