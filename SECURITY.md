# Security Policy

Package `github.com/tmc/vrf` has not received an independent security audit.

The module exposes both the RFC 9381 VRF suite and the Algorand-compatible
draft-03 suite. They are not wire-compatible; use `github.com/tmc/vrf` or
`github.com/tmc/vrf/rfc9381` for RFC 9381 proofs and `github.com/tmc/vrf/draft03`
for Algorand proofs.

## Reporting a Vulnerability

Report suspected vulnerabilities privately to Travis Cline at
<travis.cline@gmail.com>, or through GitHub's private vulnerability reporting
on the [Security tab](https://github.com/tmc/vrf/security/advisories/new).

Please do not open a public issue for a suspected vulnerability. Expect an
acknowledgement within a week.
