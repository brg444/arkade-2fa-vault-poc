package vault

import (
	"bytes"
	"testing"

	"github.com/arkade-os/emulator/poc/2fa-vault/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func testKeys(t *testing.T) (hot, offline, provider *btcec.PrivateKey, p256 []byte) {
	t.Helper()
	hot, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	offline, err = btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	provider, err = btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	p, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	return hot, offline, provider, webauthn.CompressedP256(p)
}

func TestTreesAndSavingsExclusion(t *testing.T) {
	hot, offline, provider, p256 := testKeys(t)
	op, err := NewOperational(hot.PubKey(), offline.PubKey(), provider.PubKey(), p256)
	if err != nil {
		t.Fatal(err)
	}
	if op.Leaves.Collaborative == nil || op.Leaves.Owner == nil || op.Leaves.Recovery == nil {
		t.Fatal("operational leaves")
	}
	if !op.ContainsTweakedProvider() {
		t.Fatal("operational must contain tweaked provider")
	}

	sv, err := NewSavings(hot.PubKey(), offline.PubKey(), provider.PubKey(), op.TweakedProvider)
	if err != nil {
		t.Fatal(err)
	}
	if sv.Leaves.Collaborative != nil {
		t.Fatal("savings must not have collaborative leaf")
	}
	if err := sv.AssertNoProvider(provider.PubKey(), op.TweakedProvider); err != nil {
		t.Fatal(err)
	}
	if sv.ContainsProvider(provider.PubKey()) || sv.ContainsProvider(op.TweakedProvider) {
		t.Fatal("savings contains provider key")
	}
	if err := sv.AssertNoProvider(); err == nil {
		t.Fatal("empty forbidden list must not prove exclusion")
	}

	forged := *sv
	forged.TweakedProvider = op.TweakedProvider
	if forged.ContainsTweakedProvider() || forged.ContainsProvider(op.TweakedProvider) {
		t.Fatal("TweakedProvider field must not prove leaf containment")
	}
}

func TestAuthorizationScriptExecutesOnCurrentTransaction(t *testing.T) {
	hot, offline, provider, _ := testKeys(t)
	direct, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	op, err := NewOperational(hot.PubKey(), offline.PubKey(), provider.PubKey(), webauthn.CompressedP256(direct))
	if err != nil {
		t.Fatal(err)
	}
	prevTx, opoint := fakeFund(t, op.PkScript, 80_000)
	dest, _ := txscript.PayToTaprootScript(offline.PubKey())
	spend, err := BuildCollaborativeSpend(SpendParams{
		Vault: op, PrevTx: prevTx, PrevOutPoint: opoint,
		RecipientScript: dest, RecipientAmount: 40_000, Fee: 500,
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := webauthn.SignDigestLowS(direct, spend.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err := SetPacketWitness(spend.Packet.UnsignedTx, wire.TxWitness{sig}); err != nil {
		t.Fatal(err)
	}
	if err := executeRawPacketAuthorization(spend.Packet, provider.PubKey()); err != nil {
		t.Fatal(err)
	}
	bad := append([]byte{}, sig...)
	bad[0] ^= 1
	if err := SetPacketWitness(spend.Packet.UnsignedTx, wire.TxWitness{bad}); err != nil {
		t.Fatal(err)
	}
	if err := executeRawPacketAuthorization(spend.Packet, provider.PubKey()); err == nil {
		t.Fatal("tampered direct signature accepted")
	}
}

func TestNewFromRecordRejectsInvalidKind(t *testing.T) {
	hot, offline, provider, p256 := testKeys(t)
	op, err := NewOperational(hot.PubKey(), offline.PubKey(), provider.PubKey(), p256)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []Kind{-1, 2, 99} {
		rec := op.Record
		rec.Kind = kind
		got, err := NewFromRecord(rec)
		if err == nil {
			t.Fatalf("invalid kind %d was accepted", kind)
		}
		if got != nil {
			t.Fatalf("invalid kind %d returned a %v vault", kind, got.Record.Kind)
		}
	}
	if _, err := NewFromRecord(op.Record); err != nil {
		t.Fatalf("operational record: %v", err)
	}
	sv, err := NewSavings(hot.PubKey(), offline.PubKey(), provider.PubKey(), op.TweakedProvider)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewFromRecord(sv.Record); err != nil {
		t.Fatalf("savings record: %v", err)
	}
}

func TestNewFromRecordDirectP256IsCanonical(t *testing.T) {
	hot, offline, provider, p256 := testKeys(t)
	op, err := NewOperational(hot.PubKey(), offline.PubKey(), provider.PubKey(), p256)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("empty script and hash derive from DirectP256", func(t *testing.T) {
		rec := op.Record
		rec.AuthScript = nil
		rec.AuthScriptHash = nil
		got, err := NewFromRecord(rec)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Record.AuthScript, op.Record.AuthScript) {
			t.Fatal("derived authorization script")
		}
		if !bytes.Equal(got.Record.AuthScriptHash, op.Record.AuthScriptHash) {
			t.Fatal("derived authorization script hash")
		}
	})

	t.Run("matching supplied script and hash stored as derived", func(t *testing.T) {
		got, err := NewFromRecord(op.Record)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Record.AuthScript, op.Record.AuthScript) {
			t.Fatal("matching script not stored")
		}
		if !bytes.Equal(got.Record.AuthScriptHash, op.Record.AuthScriptHash) {
			t.Fatal("matching hash not stored")
		}
	})

	t.Run("mismatched auth script rejected", func(t *testing.T) {
		rec := op.Record
		rec.AuthScript = append([]byte{}, rec.AuthScript...)
		rec.AuthScript[len(rec.AuthScript)-1] ^= 0x01
		if _, err := NewFromRecord(rec); err == nil {
			t.Fatal("mismatched auth script accepted")
		}
	})

	t.Run("mismatched auth script hash rejected", func(t *testing.T) {
		rec := op.Record
		rec.AuthScriptHash = append([]byte{}, rec.AuthScriptHash...)
		rec.AuthScriptHash[0] ^= 0x01
		if _, err := NewFromRecord(rec); err == nil {
			t.Fatal("mismatched auth script hash accepted")
		}
	})

	t.Run("empty script with mismatched hash rejected", func(t *testing.T) {
		rec := op.Record
		rec.AuthScript = nil
		rec.AuthScriptHash = append([]byte{}, rec.AuthScriptHash...)
		rec.AuthScriptHash[0] ^= 0x01
		if _, err := NewFromRecord(rec); err == nil {
			t.Fatal("mismatched hash with empty script accepted")
		}
	})

	t.Run("matching script with empty hash stores derived hash", func(t *testing.T) {
		rec := op.Record
		rec.AuthScriptHash = nil
		got, err := NewFromRecord(rec)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Record.AuthScript, op.Record.AuthScript) {
			t.Fatal("matching script not stored")
		}
		if !bytes.Equal(got.Record.AuthScriptHash, op.Record.AuthScriptHash) {
			t.Fatal("derived hash not stored")
		}
	})
}

func TestOwnerSpendRejectsNegativeChange(t *testing.T) {
	hot, offline, provider, p256 := testKeys(t)
	op, err := NewOperational(hot.PubKey(), offline.PubKey(), provider.PubKey(), p256)
	if err != nil {
		t.Fatal(err)
	}
	prevTx, opoint := fakeFund(t, op.PkScript, 10_000)
	dest, _ := txscript.PayToTaprootScript(offline.PubKey())
	if _, err := OwnerSpend(op, prevTx, opoint, dest, 20_000, 500, 0); err == nil {
		t.Fatal("overspend accepted")
	}
	if _, err := OwnerSpend(op, prevTx, opoint, dest, 100, 500, 0); err == nil {
		t.Fatal("dust dest accepted")
	}
	if _, err := OwnerSpend(nil, prevTx, opoint, dest, 5_000, 500, 0); err == nil {
		t.Fatal("nil vault accepted")
	}
	wrongHash := opoint
	wrongHash.Hash = chainhash.Hash{1}
	if _, err := OwnerSpend(op, prevTx, wrongHash, dest, 5_000, 500, 0); err == nil {
		t.Fatal("hash mismatch accepted")
	}
}

func fakeFund(t *testing.T, pk []byte, value int64) (*wire.MsgTx, wire.OutPoint) {
	t.Helper()
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{}})
	tx.AddTxOut(&wire.TxOut{Value: value, PkScript: pk})
	h := tx.TxHash()
	return tx, wire.OutPoint{Hash: h, Index: 0}
}
