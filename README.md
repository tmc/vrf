# VRF - Verifiable Random Functions

[![Go Reference](https://pkg.go.dev/badge/github.com/tmc/vrf.svg)](https://pkg.go.dev/github.com/tmc/vrf)
[![Go Report Card](https://goreportcard.com/badge/github.com/tmc/vrf)](https://goreportcard.com/report/github.com/tmc/vrf)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

A clean Go implementation of ECVRF-EDWARDS25519-SHA512-ELL2 (ciphersuite 0x04) compatible with Algorand's VRF implementation.

This implementation has been separated from Algorand's go-algorand codebase and provides a standalone, clean API for VRF operations.

## Important Note

This implementation follows **draft-irtf-cfrg-vrf-03** (the version Algorand uses) rather than the final RFC 9381 specification. See [RFC_ALIGNMENT.md](RFC_ALIGNMENT.md) for details.

- ✅ **100% compatible** with Algorand's go-algorand VRF
- ✅ Uses suite byte 0x04 (ECVRF-EDWARDS25519-SHA512-ELL2)
- ⚠️ **NOT RFC 9381 compliant** for hash-to-curve (uses simpler draft-03 approach)

## Features

- **Algorand Compatible**: Identical behavior to go-algorand VRF implementation
- **Secure**: Uses Edwards25519 curve with constant-time operations
- **Clean API**: Simple, idiomatic Go interface
- **Well-tested**: Comprehensive test suite with benchmarks and cross-validation
- **Minimal Dependencies**: Only depends on `filippo.io/edwards25519`

## Installation

```bash
go get github.com/tmc/vrf
```

## Usage

```go
package main

import (
    "crypto/rand"
    "fmt"
    "log"

    "github.com/tmc/vrf"
)

func main() {
    // Generate a random seed
    var seed [32]byte
    if _, err := rand.Read(seed[:]); err != nil {
        log.Fatal(err)
    }

    // Generate VRF key pair
    publicKey, privateKey := vrf.Keygen(seed)

    // Message to prove randomness for
    message := []byte("hello world")

    // Generate VRF proof
    proof, err := privateKey.Prove(message)
    if err != nil {
        log.Fatal(err)
    }

    // Verify proof and get deterministic output
    output, err := publicKey.Verify(proof, message)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("VRF Output: %x\n", output)
}
```

## API

### Types

- `PublicKey` - 32-byte VRF public key
- `PrivateKey` - 64-byte VRF private key (32-byte seed + 32-byte public key)  
- `Proof` - 80-byte VRF proof
- `Output` - 64-byte VRF output hash

### Functions

- `Keygen(seed [32]byte) (PublicKey, PrivateKey)` - Generate key pair from seed
- `(sk PrivateKey) Prove(message []byte) (Proof, error)` - Generate VRF proof
- `(pk PublicKey) Verify(proof Proof, message []byte) (Output, error)` - Verify proof and get output

## Security

This implementation:

- Uses constant-time operations for cryptographic computations
- Implements proper key validation (checks for small-order points)
- Uses secure random nonce generation (RFC 8032 style)
- Follows draft-irtf-cfrg-vrf-03 specification (Algorand's version)

**Note**: While this differs from RFC 9381 final in hash-to-curve implementation, it maintains the same security properties and is the standard used by Algorand's blockchain.

## Performance

Benchmarks on Apple M4 Max:

```
BenchmarkVRFProve-16     	    9910	    118424 ns/op	     752 B/op	      11 allocs/op
BenchmarkVRFVerify-16    	    7657	    154503 ns/op	     880 B/op	      13 allocs/op
```

- ~118μs per proof generation
- ~155μs per proof verification
- Minimal memory allocations

## License

GNU Affero General Public License v3.0

## References

- [draft-irtf-cfrg-vrf-03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-03) - The specification this implementation follows
- [RFC 9381: Verifiable Random Functions (VRFs)](https://tools.ietf.org/rfc/rfc9381.txt) - Final RFC (differs in hash-to-curve)
- [Algorand's libsodium VRF](https://github.com/algorand/libsodium/tree/draft-irtf-cfrg-vrf-03) - Reference C implementation
- [Edwards25519 Library](https://pkg.go.dev/filippo.io/edwards25519)