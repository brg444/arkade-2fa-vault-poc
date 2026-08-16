package policy

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestOpenLedgerRejectsStaleCredentialSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stale.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
CREATE TABLE credential (
  id INTEGER PRIMARY KEY,
  credential_id BLOB NOT NULL,
  p256_compressed BLOB NOT NULL,
  rp_id TEXT NOT NULL,
  origin TEXT NOT NULL,
  created_at TEXT NOT NULL
);`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	_, err = OpenLedger(path, nil)
	if err == nil || !strings.Contains(err.Error(), "incompatible vault database") || !strings.Contains(err.Error(), "do not delete authoritative deployment data") {
		t.Fatalf("want stale schema error, got %v", err)
	}
}

func TestOpenLedgerRejectsV2RoleSchemaWithoutReinterpretation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "funded-v2.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// These role names intentionally model the pre-v3 credential layout. In
	// particular, hot/offline cannot be reinterpreted as PhoneRoutineBIP340
	// and the independent ExternalOwnerWallet+RecoveryKey pair.
	if _, err := db.Exec(`
CREATE TABLE credential (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  credential_id BLOB NOT NULL,
  webauthn_p256_compressed BLOB NOT NULL,
  direct_p256_compressed BLOB NOT NULL,
  hot_bip340_compressed BLOB NOT NULL,
  offline_compressed BLOB NOT NULL,
  provider_base_compressed BLOB NOT NULL,
  tweaked_provider_compressed BLOB NOT NULL,
  template_version TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  integrity_mac BLOB NOT NULL
);`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	_, err = OpenLedger(path, nil)
	if err == nil || !strings.Contains(err.Error(), "incompatible vault database") ||
		!strings.Contains(err.Error(), "do not delete authoritative deployment data") {
		t.Fatalf("v2 role schema was reinterpreted or not safely rejected: %v", err)
	}
}

func TestOpenLedgerRejectsMalformedIssuanceSchemaAfterPartialCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "malformed-issuance.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE issuance (vault_id TEXT)`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	// The first open may create credential before CREATE TABLE issuance fails.
	if led, err := OpenLedger(path, nil); err == nil {
		_ = led.Close()
		t.Fatal("malformed preexisting issuance table accepted")
	}
	// A restart must inspect issuance itself rather than accepting its name.
	_, err = OpenLedger(path, nil)
	if err == nil || !strings.Contains(err.Error(), "issuance columns") || !strings.Contains(err.Error(), "do not delete authoritative deployment data") {
		t.Fatalf("malformed issuance schema was not rejected on restart: %v", err)
	}
}

func TestOpenLedgerRejectsIssuanceColumnsWithoutStagedStateConstraints(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-staged-constraint.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	broken := strings.Replace(
		createPOCSchema,
		"state TEXT NOT NULL CHECK (state IN ('reserved', 'vault_signed', 'completed'))",
		"state TEXT NOT NULL",
		1,
	)
	if broken == createPOCSchema {
		t.Fatal("test failed to remove staged-state constraint")
	}
	if _, err := db.Exec(broken); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	_, err = OpenLedger(path, nil)
	if err == nil || !strings.Contains(err.Error(), "issuance constraints") || !strings.Contains(err.Error(), "do not delete authoritative deployment data") {
		t.Fatalf("same-column issuance table without state constraint was accepted: %v", err)
	}
}
