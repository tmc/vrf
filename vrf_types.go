// Copyright (C) 2019-2023 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package crypto

import vrf "github.com/tmc/go-algorand/crypto/vrf"

// VRF type aliases for backward compatibility

type (
	VrfOutput  = vrf.VrfOutput
	VrfPrivkey = vrf.VrfPrivkey
	VrfProof   = vrf.VrfProof
	VrfPubkey  = vrf.VrfPubkey

	VRFVerifier = vrf.VrfPubkey
	VRFProof    = vrf.VrfProof
	VRFSecrets  = vrf.VRFSecrets
)

var (
	VRFSecretsMaxSize   = vrf.VRFSecretsMaxSize
	VrfKeygen           = vrf.VrfKeygen
	VrfKeygenFromSeed   = vrf.VrfKeygenFromSeed
	VrfKeygenFromSeedGo = vrf.VrfKeygenFromSeedGo
	VrfOutputMaxSize    = vrf.VrfOutputMaxSize
	VrfPrivkeyMaxSize   = vrf.VrfPrivkeyMaxSize
	VrfProofMaxSize     = vrf.VrfProofMaxSize
	VrfPubkeyMaxSize    = vrf.VrfPubkeyMaxSize
	VRFVerifierMaxSize  = vrf.VrfPubkeyMaxSize
)

// GenerateVRFSecrets is deprecated, use VrfKeygen or VrfKeygenFromSeed instead
// DEPRECATED: Use VrfKeygen or VrfKeygenFromSeed instead
func GenerateVRFSecrets() *VRFSecrets {
	s := new(vrf.VRFSecrets)
	s.PK, s.SK = vrf.VrfKeygen()
	return s
}
