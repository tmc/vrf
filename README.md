# VRF - Verifiable Random Functions

A clean Go implementation of ECVRF-EDWARDS25519-SHA512-ELL2 (ciphersuite 0x04) from [RFC 9381](https://tools.ietf.org/rfc/rfc9381.txt).

This implementation has been separated from Algorand's go-algorand codebase and provides a standalone, clean API for VRF operations.

## Features

- **RFC 9381 Compliant**: Implements ECVRF-EDWARDS25519-SHA512-ELL2 ciphersuite
- **Secure**: Uses Edwards25519 curve with constant-time operations
- **Clean API**: Simple, idiomatic Go interface
- **Well-tested**: Comprehensive test suite with benchmarks
- **Zero Dependencies**: Only depends on `filippo.io/edwards25519`

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
- Uses secure random nonce generation
- Follows RFC 9381 specification exactly

## Performance

Benchmarks on Apple M4 Max:

```
BenchmarkVRFProve-16     	    9912	    114819 ns/op
BenchmarkVRFVerify-16    	    8161	    149560 ns/op
```

## License

GNU Affero General Public License v3.0

## References

- [RFC 9381: Verifiable Random Functions (VRFs)](https://tools.ietf.org/rfc/rfc9381.txt)
- [Edwards25519 Library](https://pkg.go.dev/filippo.io/edwards25519)