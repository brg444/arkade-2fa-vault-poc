package webauthn

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
)

const flagAT = 1 << 6

// ValidateCreate checks a WebAuthn create ceremony against the pending
// challenge, origin, and RP ID. It does not verify an attestation statement.
func ValidateCreate(clientDataJSON, authenticatorData, challenge []byte, origin, rpID string) (credID []byte, err error) {
	if len(challenge) != 32 {
		return nil, fmt.Errorf("challenge must be 32 bytes")
	}
	if len(authenticatorData) < 37 {
		return nil, fmt.Errorf("authenticatorData too short")
	}
	var cd ClientData
	if err := json.Unmarshal(clientDataJSON, &cd); err != nil {
		return nil, fmt.Errorf("clientDataJSON: %w", err)
	}
	if cd.Type != "webauthn.create" {
		return nil, fmt.Errorf("clientDataJSON type %q", cd.Type)
	}
	if cd.Origin != origin {
		return nil, fmt.Errorf("origin")
	}
	if cd.CrossOrigin == nil || *cd.CrossOrigin {
		return nil, fmt.Errorf("crossOrigin must be false")
	}
	gotChallenge, err := decodeChallenge(cd.Challenge)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(gotChallenge, challenge) {
		return nil, fmt.Errorf("challenge mismatch")
	}
	rpHash := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(authenticatorData[:32], rpHash[:]) {
		return nil, fmt.Errorf("rpIdHash mismatch")
	}
	flags := authenticatorData[32]
	if flags&flagUP == 0 {
		return nil, fmt.Errorf("user presence required")
	}
	if flags&flagUV == 0 {
		return nil, fmt.Errorf("user verification required")
	}
	if flags&flagAT == 0 {
		return nil, nil
	}
	return extractAttestedCredentialID(authenticatorData)
}

func extractAttestedCredentialID(auth []byte) ([]byte, error) {
	// rpHash(32) + flags(1) + signCount(4) + AAGUID(16) + credIdLen(2) + credId
	const prefix = 37 + 16 + 2
	if len(auth) < prefix {
		return nil, fmt.Errorf("attested credential data truncated")
	}
	credLen := binary.BigEndian.Uint16(auth[53:55])
	if credLen == 0 || int(prefix)+int(credLen) > len(auth) {
		return nil, fmt.Errorf("attested credential id truncated")
	}
	return append([]byte(nil), auth[prefix:prefix+int(credLen)]...), nil
}
