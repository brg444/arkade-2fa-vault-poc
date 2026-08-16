package vault

import (
	"crypto/ecdsa"
	"math"
	"testing"

	"github.com/arkade-os/emulator/poc/2fa-vault/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	securityPrevoutValue  = int64(200_000)
	securityRecipientSats = int64(40_000)
	securityFeeSats       = int64(1_000)
)

type securityVaultFixture struct {
	hot          *btcec.PrivateKey
	offline      *btcec.PrivateKey
	provider     *btcec.PrivateKey
	arkade       *btcec.PrivateKey
	direct       *ecdsa.PrivateKey
	recipient    *btcec.PrivateKey
	operational  *Built
	savings      *Built
	prevTx       *wire.MsgTx
	prevOutPoint wire.OutPoint
	recipientPK  []byte
}

func newSecurityVaultFixture(t *testing.T) *securityVaultFixture {
	t.Helper()

	hot := mustSecurityK1Key(t)
	offline := mustSecurityK1Key(t)
	provider := mustSecurityK1Key(t)
	arkade := mustSecurityK1Key(t)
	recipient := mustSecurityK1Key(t)
	p256, err := webauthn.NewP256()
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	operational, err := NewOperational(OperationalKeys{
		Hot:          hot.PubKey(),
		Offline:      offline.PubKey(),
		ProviderBase: provider.PubKey(),
		ArkadeBase:   arkade.PubKey(),
		DirectP256:   webauthn.CompressedP256(p256),
	})
	if err != nil {
		t.Fatalf("build Operational vault: %v", err)
	}
	savings, err := NewSavings(
		hot.PubKey(), offline.PubKey(),
		provider.PubKey(), operational.TweakedProvider,
		arkade.PubKey(), operational.TweakedArkade,
	)
	if err != nil {
		t.Fatalf("build Savings vault: %v", err)
	}
	recipientPK, err := txscript.PayToTaprootScript(recipient.PubKey())
	if err != nil {
		t.Fatalf("recipient P2TR script: %v", err)
	}

	prevTx := wire.NewMsgTx(2)
	prevTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Index: math.MaxUint32},
		Sequence:         wire.MaxTxInSequenceNum,
	})
	prevTx.AddTxOut(&wire.TxOut{Value: securityPrevoutValue, PkScript: operational.PkScript})

	return &securityVaultFixture{
		hot:          hot,
		offline:      offline,
		provider:     provider,
		arkade:       arkade,
		direct:       p256,
		recipient:    recipient,
		operational:  operational,
		savings:      savings,
		prevTx:       prevTx,
		prevOutPoint: wire.OutPoint{Hash: prevTx.TxHash(), Index: 0},
		recipientPK:  recipientPK,
	}
}

func (f *securityVaultFixture) collaborativeParams() SpendParams {
	return SpendParams{
		Vault:           f.operational,
		PrevTx:          f.prevTx,
		PrevOutPoint:    f.prevOutPoint,
		RecipientScript: append([]byte(nil), f.recipientPK...),
		RecipientAmount: securityRecipientSats,
		Fee:             securityFeeSats,
	}
}

func mustSecurityK1Key(t *testing.T) *btcec.PrivateKey {
	t.Helper()
	key, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("generate secp256k1 key: %v", err)
	}
	return key
}

func cloneSecurityTx(tx *wire.MsgTx) *wire.MsgTx {
	return tx.Copy()
}
