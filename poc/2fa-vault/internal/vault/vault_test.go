package vault

import (
	"bytes"
	"strings"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/emulator/poc/2fa-vault/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func testKeys(t *testing.T) (hot, offline, provider, arkade *btcec.PrivateKey, p256 []byte) {
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
	arkade, err = btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	p, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	return hot, offline, provider, arkade, webauthn.CompressedP256(p)
}

func TestTreesAndSavingsExclusion(t *testing.T) {
	hot, offline, provider, arkade, p256 := testKeys(t)
	op, err := NewOperational(OperationalKeys{Hot: hot.PubKey(), Offline: offline.PubKey(), ProviderBase: provider.PubKey(), ArkadeBase: arkade.PubKey(), DirectP256: p256})
	if err != nil {
		t.Fatal(err)
	}
	if op.Leaves.Collaborative == nil || op.Leaves.Owner == nil || op.Leaves.Recovery == nil {
		t.Fatal("operational leaves")
	}
	if !op.ContainsTweakedProvider() {
		t.Fatal("operational must contain tweaked provider")
	}
	if !op.ContainsTweakedArkade() {
		t.Fatal("operational must contain tweaked arkade emulator")
	}

	sv, err := NewSavings(hot.PubKey(), offline.PubKey(), provider.PubKey(), op.TweakedProvider, arkade.PubKey(), op.TweakedArkade)
	if err != nil {
		t.Fatal(err)
	}
	if sv.Leaves.Collaborative != nil {
		t.Fatal("savings must not have collaborative leaf")
	}
	if err := sv.AssertNoProvider(provider.PubKey(), op.TweakedProvider, arkade.PubKey(), op.TweakedArkade); err != nil {
		t.Fatal(err)
	}
	if sv.ContainsProvider(provider.PubKey()) || sv.ContainsProvider(op.TweakedProvider) || sv.ContainsProvider(arkade.PubKey()) || sv.ContainsProvider(op.TweakedArkade) {
		t.Fatal("savings contains collaborative signer key")
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

func TestMutinynetTreeUsesPinnedCustomSignetParamsAndExplicitDelays(t *testing.T) {
	hot, offline, provider, arkade, p256 := testKeys(t)
	opCSV := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 288}
	savingsCSV := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 4032}
	op, err := NewOperationalWithPolicy(OperationalKeys{Hot: hot.PubKey(), Offline: offline.PubKey(), ProviderBase: provider.PubKey(), ArkadeBase: arkade.PubKey(), DirectP256: p256}, "mutinynet", opCSV, fixtureAuthorizationPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(op.Address, "tb1p") || op.Record.Network != "mutinynet" || op.Record.CSV != opCSV {
		t.Fatalf("mutinynet operational descriptor: address=%s network=%s csv=%+v", op.Address, op.Record.Network, op.Record.CSV)
	}
	sv, err := NewSavingsWithPolicy(hot.PubKey(), offline.PubKey(), "mutinynet", savingsCSV, provider.PubKey(), op.TweakedProvider, arkade.PubKey(), op.TweakedArkade)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sv.Address, "tb1p") || sv.Record.Network != "mutinynet" || sv.Record.CSV != savingsCSV {
		t.Fatalf("mutinynet savings descriptor: address=%s network=%s csv=%+v", sv.Address, sv.Record.Network, sv.Record.CSV)
	}
}

func TestVaultRolesAreDistinctByXOnlyIdentity(t *testing.T) {
	hot, offline, provider, arkade, p256 := testKeys(t)
	negatedHot := negateTestPub(t, hot.PubKey())
	negatedOffline := negateTestPub(t, offline.PubKey())
	for _, test := range []struct {
		name  string
		build func() error
	}{
		{name: "owner hot equals offline", build: func() error {
			_, err := NewSavings(negatedOffline, offline.PubKey(), provider.PubKey())
			return err
		}},
		{name: "provider equals hot", build: func() error {
			_, err := NewOperational(OperationalKeys{Hot: hot.PubKey(), Offline: offline.PubKey(), ProviderBase: negatedHot, ArkadeBase: arkade.PubKey(), DirectP256: p256})
			return err
		}},
		{name: "provider equals offline", build: func() error {
			_, err := NewOperational(OperationalKeys{Hot: hot.PubKey(), Offline: offline.PubKey(), ProviderBase: negatedOffline, ArkadeBase: arkade.PubKey(), DirectP256: p256})
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.build(); err == nil || !strings.Contains(err.Error(), "independent") {
				t.Fatalf("collapsed key roles accepted: %v", err)
			}
		})
	}
	if err := requireIndependentXOnly(provider.PubKey(), negateTestPub(t, provider.PubKey()), hot.PubKey(), offline.PubKey()); err == nil || !strings.Contains(err.Error(), "independent") {
		t.Fatalf("provider base and x-only-identical tweaked provider accepted: %v", err)
	}
}

func negateTestPub(t *testing.T, pub *btcec.PublicKey) *btcec.PublicKey {
	t.Helper()
	raw := append([]byte(nil), pub.SerializeCompressed()...)
	raw[0] ^= 1
	negated, err := btcec.ParsePubKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return negated
}

func TestAuthorizationScriptExecutesOnCurrentTransaction(t *testing.T) {
	hot, offline, provider, arkade, _ := testKeys(t)
	direct, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	op, err := NewOperational(OperationalKeys{Hot: hot.PubKey(), Offline: offline.PubKey(), ProviderBase: provider.PubKey(), ArkadeBase: arkade.PubKey(), DirectP256: webauthn.CompressedP256(direct)})
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
	hot, offline, provider, arkade, p256 := testKeys(t)
	op, err := NewOperational(OperationalKeys{Hot: hot.PubKey(), Offline: offline.PubKey(), ProviderBase: provider.PubKey(), ArkadeBase: arkade.PubKey(), DirectP256: p256})
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
	sv, err := NewSavings(hot.PubKey(), offline.PubKey(), provider.PubKey(), op.TweakedProvider, arkade.PubKey(), op.TweakedArkade)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewFromRecord(sv.Record); err != nil {
		t.Fatalf("savings record: %v", err)
	}
}

func TestNewFromRecordDirectP256IsCanonical(t *testing.T) {
	hot, offline, provider, arkade, p256 := testKeys(t)
	op, err := NewOperational(OperationalKeys{Hot: hot.PubKey(), Offline: offline.PubKey(), ProviderBase: provider.PubKey(), ArkadeBase: arkade.PubKey(), DirectP256: p256})
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
	hot, offline, provider, arkade, p256 := testKeys(t)
	op, err := NewOperational(OperationalKeys{Hot: hot.PubKey(), Offline: offline.PubKey(), ProviderBase: provider.PubKey(), ArkadeBase: arkade.PubKey(), DirectP256: p256})
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
