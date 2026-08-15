package vault

import (
	"bytes"
	"crypto/elliptic"
	"testing"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/emulator/poc/2fa-vault/internal/webauthn"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func TestAuthorizationScriptIsExactStaticP256Program(t *testing.T) {
	t.Parallel()

	priv, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	compressed := webauthn.CompressedP256(priv)
	got, err := AuthorizationScript(compressed)
	if err != nil {
		t.Fatal(err)
	}
	extendedKey := append([]byte{0x11}, compressed...)
	want, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_0).
		AddOp(arkade.OP_SIGHASH).
		AddData(extendedKey).
		AddOp(arkade.OP_CHECKSIGFROMSTACK).
		Script()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("authorization script = %x, want %x", got, want)
	}
}

// WebAuthn assertion fields are provider-side ceremony evidence, not the
// Arkade witness. The direct-signer program must reject the legacy three-item
// witness instead of putting clientDataJSON/authenticatorData on-chain.
func TestAuthorizationScriptRejectsLegacyWebAuthnWireWitness(t *testing.T) {
	t.Parallel()

	directKey, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	webauthnKey, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}

	f := newSecurityVaultFixture(t)
	op, err := NewOperational(
		f.hot.PubKey(), f.offline.PubKey(), f.provider.PubKey(),
		webauthn.CompressedP256(directKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	prevTx := f.prevTx.Copy()
	prevTx.TxOut[0].PkScript = append([]byte(nil), op.PkScript...)
	params := f.collaborativeParams()
	params.Vault = op
	params.PrevTx = prevTx
	params.PrevOutPoint.Hash = prevTx.TxHash()
	spend, err := BuildCollaborativeSpend(params)
	if err != nil {
		t.Fatal(err)
	}

	directSig := signDirectP256LowS(t, directKey, spend.Challenge)
	if err := SetPacketWitness(spend.Packet.UnsignedTx, wire.TxWitness{directSig}); err != nil {
		t.Fatal(err)
	}
	if err := executeRawPacketAuthorization(spend.Packet, f.provider.PubKey()); err != nil {
		t.Fatalf("test setup failed: one-item direct signature was rejected: %v", err)
	}

	assertion, err := webauthn.Synth(
		webauthnKey, []byte("credential"), spend.Challenge,
		"http://localhost:8787", "localhost", true, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := webauthn.CompactLowS(assertion.DERSignature)
	if err != nil {
		t.Fatal(err)
	}
	witness := wire.TxWitness{compact, assertion.AuthenticatorData, assertion.ClientDataJSON}
	if err := SetPacketWitness(spend.Packet.UnsignedTx, witness); err != nil {
		t.Fatal(err)
	}
	if err := executeRawPacketAuthorization(spend.Packet, f.provider.PubKey()); err == nil {
		t.Fatal("direct authorization script accepted legacy WebAuthn assertion witness")
	}
}

func TestAuthorizationScriptRejectsWrongP256KeyLength(t *testing.T) {
	t.Parallel()

	for _, size := range []int{0, 32, 34} {
		if _, err := AuthorizationScript(make([]byte, size)); err == nil {
			t.Fatalf("AuthorizationScript accepted %d-byte P-256 key", size)
		}
	}
}

func TestAuthorizationScriptRejectsOffCurveAndNoncanonicalP256(t *testing.T) {
	t.Parallel()

	priv, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	valid := webauthn.CompressedP256(priv)
	if _, err := AuthorizationScript(valid); err != nil {
		t.Fatalf("valid compressed DirectP256: %v", err)
	}

	offCurve := make([]byte, 33)
	offCurve[0] = 0x02
	elliptic.P256().Params().P.FillBytes(offCurve[1:])

	wrongPrefix := append([]byte{0x04}, valid[1:]...)
	hybrid := append([]byte{0x06}, valid[1:]...)

	for name, key := range map[string][]byte{
		"off-curve x=p":       offCurve,
		"uncompressed prefix": wrongPrefix,
		"hybrid prefix":       hybrid,
	} {
		if _, err := AuthorizationScript(key); err == nil {
			t.Fatalf("AuthorizationScript accepted %s key %x", name, key)
		}
	}
}
