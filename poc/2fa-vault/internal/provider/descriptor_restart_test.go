package provider

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arkade-os/emulator/poc/2fa-vault/fixture"
	"github.com/arkade-os/emulator/poc/2fa-vault/internal/policy"
	"github.com/arkade-os/emulator/poc/2fa-vault/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	_ "modernc.org/sqlite"
)

func TestLoadVaultsRebuildsFromStoredDescriptorNotRuntimeKeys(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "descriptor.sqlite")
	ledger, err := policy.OpenLedger(dbPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })

	hot, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	offline, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	providerKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	arkadeKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	p256, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	direct, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	enrolled := &Service{
		Ledger:      ledger,
		Offline:     offline.PubKey(),
		ProviderPub: providerKey.PubKey(),
		ArkadePub:   arkadeKey.PubKey(),
		Signer:      LocalSigner{Priv: providerKey},
		ArkadeSigner: LocalSigner{
			Priv: arkadeKey,
		},
	}
	if err := enrolled.Register(RegisterRequest{
		CredentialID: hex.EncodeToString([]byte("descriptor-cred")),
		WebAuthnP256: hex.EncodeToString(webauthn.CompressedP256(p256)),
		DirectP256:   hex.EncodeToString(webauthn.CompressedP256(direct)),
		HotPub:       hex.EncodeToString(hot.PubKey().SerializeCompressed()),
	}); err != nil {
		t.Fatal(err)
	}
	wantOp := enrolled.Operational.Address
	wantSv := enrolled.Savings.Address
	wantTweak := schnorr.SerializePubKey(enrolled.Operational.TweakedProvider)
	wantArkadeTweak := schnorr.SerializePubKey(enrolled.Operational.TweakedArkade)
	persisted, err := ledger.GetCredential()
	if err != nil || persisted == nil {
		t.Fatalf("persisted enrollment: %v", err)
	}

	otherOffline, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	rotatedArkade, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("live structurally valid authentication key substitution refused by MAC", func(t *testing.T) {
		alternate, err := webauthn.NewP256()
		if err != nil {
			t.Fatal(err)
		}
		execCredentialUpdate(t, dbPath, `UPDATE credential SET direct_p256_compressed = ?`, webauthn.CompressedP256(alternate))
		t.Cleanup(func() {
			execCredentialUpdate(t, dbPath, `UPDATE credential SET direct_p256_compressed = ?`, persisted.DirectP256)
		})
		restart, err := policy.OpenLedger(dbPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = restart.Close() })
		svc := &Service{Ledger: restart, Offline: offline.PubKey(), ProviderPub: providerKey.PubKey()}
		if err := svc.LoadVaults(); err == nil || !strings.Contains(err.Error(), "credential integrity") {
			t.Fatalf("live credential substitution was not rejected before publish: %v", err)
		}
	})

	t.Run("all persisted derived descriptor outputs corrupted together refused by MAC", func(t *testing.T) {
		alternate, err := btcec.NewPrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		execCredentialUpdate(t, dbPath, `UPDATE credential SET
			operational_address = ?, operational_script = ?, savings_address = ?, savings_script = ?, tweaked_provider_compressed = ?`,
			"bcrt1pmodified-operational", []byte{0x51, 0x20, 0x01},
			"bcrt1pmodified-savings", []byte{0x51, 0x20, 0x02}, alternate.PubKey().SerializeCompressed())
		t.Cleanup(func() {
			execCredentialUpdate(t, dbPath, `UPDATE credential SET
				operational_address = ?, operational_script = ?, savings_address = ?, savings_script = ?, tweaked_provider_compressed = ?`,
				persisted.OperationalAddress, persisted.OperationalScript,
				persisted.SavingsAddress, persisted.SavingsScript, persisted.TweakedProvider)
		})
		restart, err := policy.OpenLedger(dbPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = restart.Close() })
		svc := &Service{Ledger: restart, Offline: offline.PubKey(), ProviderPub: providerKey.PubKey()}
		if err := svc.LoadVaults(); err == nil || !strings.Contains(err.Error(), "credential integrity") {
			t.Fatalf("derived descriptor corruption was not rejected before rebuild: %v", err)
		}
	})

	t.Run("stored origin mismatch refused", func(t *testing.T) {
		tamperCredential(t, dbPath, `UPDATE credential SET origin = ?`, "https://evil.example")
		t.Cleanup(func() { tamperCredential(t, dbPath, `UPDATE credential SET origin = ?`, fixture.Origin) })
		restart, err := policy.OpenLedger(dbPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = restart.Close() })
		svc := &Service{
			Ledger:      restart,
			Offline:     offline.PubKey(),
			ProviderPub: providerKey.PubKey(),
		}
		if err := svc.LoadVaults(); err == nil {
			t.Fatal("LoadVaults accepted a stored origin that does not match runtime")
		}
	})

	t.Run("stored rp id mismatch refused", func(t *testing.T) {
		tamperCredential(t, dbPath, `UPDATE credential SET rp_id = ?`, "evil.example")
		t.Cleanup(func() { tamperCredential(t, dbPath, `UPDATE credential SET rp_id = ?`, fixture.RPID) })
		restart, err := policy.OpenLedger(dbPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = restart.Close() })
		svc := &Service{
			Ledger:      restart,
			Offline:     offline.PubKey(),
			ProviderPub: providerKey.PubKey(),
		}
		if err := svc.LoadVaults(); err == nil {
			t.Fatal("LoadVaults accepted a stored RP ID that does not match runtime")
		}
	})

	t.Run("offline mismatch refused", func(t *testing.T) {
		restart, err := policy.OpenLedger(dbPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = restart.Close() })
		svc := &Service{
			Ledger:      restart,
			Offline:     otherOffline.PubKey(),
			ProviderPub: providerKey.PubKey(),
		}
		if err := svc.LoadVaults(); err == nil {
			t.Fatal("LoadVaults accepted a different offline pubkey")
		}
	})

	t.Run("rotated signer without deprecated list refused", func(t *testing.T) {
		restart, err := policy.OpenLedger(dbPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = restart.Close() })
		svc := &Service{
			Ledger:      restart,
			Offline:     offline.PubKey(),
			ProviderPub: rotated.PubKey(),
		}
		if err := svc.LoadVaults(); err == nil {
			t.Fatal("LoadVaults accepted a rotated provider key with no deprecated list")
		}
	})

	t.Run("deprecated current signer rebuilds stored tweak", func(t *testing.T) {
		restart, err := policy.OpenLedger(dbPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = restart.Close() })
		remote := &RemoteSigner{}
		svc := &Service{
			Ledger:             restart,
			Offline:            offline.PubKey(),
			ProviderPub:        rotated.PubKey(),
			DeprecatedProvider: []*btcec.PublicKey{providerKey.PubKey()},
			Signer:             remote,
		}
		if err := svc.LoadVaults(); err != nil {
			t.Fatalf("LoadVaults with deprecated enrolled key: %v", err)
		}
		if svc.Operational.Address != wantOp || svc.Savings.Address != wantSv {
			t.Fatalf("restart derived different addresses: op %s want %s, sv %s want %s",
				svc.Operational.Address, wantOp, svc.Savings.Address, wantSv)
		}
		if !bytes.Equal(svc.ProviderPub.SerializeCompressed(), providerKey.PubKey().SerializeCompressed()) {
			t.Fatal("runtime provider was not replaced with the stored enrolled base key")
		}
		if !bytes.Equal(remote.ExpectedXOnly, wantTweak) {
			t.Fatal("RemoteSigner expected key was not the stored tweaked provider")
		}
		if !bytes.Equal(svc.Operational.TweakedProvider.SerializeCompressed(), enrolled.Operational.TweakedProvider.SerializeCompressed()) {
			t.Fatal("rebuilt tweaked provider does not match enrollment")
		}
	})

	t.Run("active deprecated arkade signer rebuilds its exact stored tweak", func(t *testing.T) {
		restart, err := policy.OpenLedger(dbPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = restart.Close() })
		remote := &RemoteSigner{}
		svc := &Service{
			Ledger:           restart,
			Offline:          offline.PubKey(),
			ProviderPub:      providerKey.PubKey(),
			ArkadePub:        rotatedArkade.PubKey(),
			DeprecatedArkade: []*btcec.PublicKey{arkadeKey.PubKey()},
			ArkadeSigner:     remote,
		}
		if err := svc.LoadVaults(); err != nil {
			t.Fatalf("LoadVaults with actively deprecated Arkade key: %v", err)
		}
		if !bytes.Equal(svc.ArkadePub.SerializeCompressed(), arkadeKey.PubKey().SerializeCompressed()) {
			t.Fatal("runtime Arkade identity was not replaced with the exact enrolled base key")
		}
		if !bytes.Equal(remote.ExpectedXOnly, wantArkadeTweak) {
			t.Fatal("public signer expected key was not the stored tweaked Arkade identity")
		}
		if svc.Operational.Address != wantOp || svc.Savings.Address != wantSv {
			t.Fatal("active-deprecated Arkade restart changed enrolled addresses")
		}
	})
}

func tamperCredential(t *testing.T, dbPath, query, value string) {
	execCredentialUpdate(t, dbPath, query, value)
}

func execCredentialUpdate(t *testing.T, dbPath, query string, args ...any) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`PRAGMA busy_timeout = 5000`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}
