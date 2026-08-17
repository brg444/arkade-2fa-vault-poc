package webauthn

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func TestValidateCreateChecksTypeChallengeAndFlags(t *testing.T) {
	challenge := bytes32(0xaa)
	origin := "https://vault.example.com"
	rpID := "vault.example.com"
	cd := []byte(`{"type":"webauthn.create","challenge":"` + EncodeChallenge(challenge) + `","origin":"` + origin + `","crossOrigin":false}`)
	auth := make([]byte, 37)
	sum := sha256.Sum256([]byte(rpID))
	copy(auth[:32], sum[:])
	auth[32] = flagUP | flagUV
	if _, err := ValidateCreate(cd, auth, challenge, origin, rpID); err != nil {
		t.Fatal(err)
	}

	get := []byte(`{"type":"webauthn.get","challenge":"` + EncodeChallenge(challenge) + `","origin":"` + origin + `","crossOrigin":false}`)
	if _, err := ValidateCreate(get, auth, challenge, origin, rpID); err == nil {
		t.Fatal("accepted a get ceremony as create")
	}

	authAT := make([]byte, 55+4)
	copy(authAT, auth)
	authAT[32] = flagUP | flagUV | flagAT
	binary.BigEndian.PutUint16(authAT[53:55], 4)
	copy(authAT[55:59], []byte{1, 2, 3, 4})
	got, err := ValidateCreate(cd, authAT, challenge, origin, rpID)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "\x01\x02\x03\x04" {
		t.Fatalf("attested cred id = %x", got)
	}
}

func bytes32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}
