# Security Policy

Package `github.com/tmc/vrf` has not received an independent security audit.

The module exposes both the RFC 9381 VRF suite and the Algorand-compatible
draft-03 suite. They are not wire-compatible; use `github.com/tmc/vrf` or
`github.com/tmc/vrf/rfc9381` for RFC 9381 proofs and `github.com/tmc/vrf/draft03`
for Algorand proofs.

Report suspected vulnerabilities privately to Travis Cline.
