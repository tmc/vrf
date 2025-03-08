# VRF - Verifiable Random Function Implementation

This repository contains a pure Go implementation of the ECVRF-ED25519-SHA512-Elligator2 (suite 0x04) as described in [RFC 9381](./docs/rfc9381.txt).

## Overview

A Verifiable Random Function (VRF) is a cryptographic primitive that maps inputs to verifiable pseudorandom outputs. 
The owner of the VRF private key can compute the VRF output and provide a proof that the output was computed correctly.
Anyone with the public key can verify this proof.

This implementation:

- Uses Ed25519 elliptic curve
- Implements ECVRF-ED25519-SHA512-Elligator2 (suite 0x04)
- Written in pure Go
- Depends on [filippo.io/edwards25519](https://github.com/FiloSottile/edwards25519)

## License

This code is licensed under the MIT License.
