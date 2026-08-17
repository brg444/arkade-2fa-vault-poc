package policy

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
)

// BackupSQLiteIfAbsent writes a consistent snapshot of the verified live v3
// credential to dest via VACUUM INTO when dest does not exist. An existing
// dest is accepted only after SQLite integrity, exact v3 schema validation,
// and an identity match against the live record. The v4 migration is
// forward-only: restore this file and the pre-v4 binary to roll back.
func (l *Ledger) BackupSQLiteIfAbsent(dest string) error {
	if dest == "" {
		return fmt.Errorf("backup path required")
	}
	if len(l.integrityKey) != sha256.Size {
		return fmt.Errorf("integrity key required to verify backup")
	}
	live, err := l.GetCredential()
	if err != nil {
		return err
	}
	if live != nil {
		if err := VerifyCredentialIntegrity(live, l.integrityKey); err != nil {
			return fmt.Errorf("live v3 credential: %w", err)
		}
		if live.VaultID != LegacyFirstVaultID {
			return fmt.Errorf("legacy fallback applies only to %s", LegacyFirstVaultID)
		}
	}

	if _, err := os.Stat(dest); err == nil {
		return acceptExistingBackup(dest, live, l.integrityKey)
	} else if !os.IsNotExist(err) {
		return err
	}
	if live == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return err
	}
	if _, err := l.db.Exec(`VACUUM INTO ?`, dest); err != nil {
		_ = os.Remove(dest)
		return fmt.Errorf("sqlite backup: %w", err)
	}
	if err := acceptExistingBackup(dest, live, l.integrityKey); err != nil {
		_ = os.Remove(dest)
		return fmt.Errorf("new backup failed validation: %w", err)
	}
	return nil
}

func acceptExistingBackup(dest string, live *Credential, integrityKey []byte) error {
	db, err := sql.Open("sqlite", dest)
	if err != nil {
		return fmt.Errorf("open backup: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if err := requireSQLiteIntegrity(db); err != nil {
		return fmt.Errorf("backup integrity: %w", err)
	}
	if err := validateV3Schema(db, dest); err != nil {
		return fmt.Errorf("backup schema: %w", err)
	}
	stored, err := loadCredential(db)
	if err != nil {
		return fmt.Errorf("backup credential: %w", err)
	}
	if stored != nil {
		if err := VerifyCredentialIntegrity(stored, integrityKey); err != nil {
			return fmt.Errorf("backup credential: %w", err)
		}
		if stored.VaultID != LegacyFirstVaultID {
			return fmt.Errorf("backup vault id %q, want %s", stored.VaultID, LegacyFirstVaultID)
		}
	}
	if err := credentialIdentitiesEqual(stored, live); err != nil {
		return fmt.Errorf("backup identity mismatch (%v)", err)
	}
	return nil
}

func requireSQLiteIntegrity(db *sql.DB) error {
	var status string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&status); err != nil {
		return err
	}
	if status != "ok" {
		return fmt.Errorf("integrity_check = %s", status)
	}
	return nil
}

func validateV3Schema(db *sql.DB, path string) error {
	if err := validateV3CoreSchema(db, path); err != nil {
		return err
	}
	return validateCredentialEnvelopeSchema(db, path)
}

func validateV3CoreSchema(db *sql.DB, path string) error {
	cols, err := tableColumns(db, "credential")
	if err != nil {
		return fmt.Errorf("incompatible vault database %s: %w", path, err)
	}
	if !sameColumns(cols, credentialColumns) {
		return fmt.Errorf("incompatible vault database %s: credential columns %v, want %v; do not delete authoritative deployment data: stop the signer and restore a verified compatible backup or use a reviewed migration", path, cols, credentialColumns)
	}
	if err := requireSchemaFragments(db, "credential", []string{
		"id INTEGER PRIMARY KEY CHECK (id = 1)",
	}); err != nil {
		return fmt.Errorf("incompatible vault database %s: credential constraints: %w; do not delete authoritative deployment data: stop the signer and restore a verified compatible backup or use a reviewed migration", path, err)
	}
	var issuance string
	err = db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='issuance'`).Scan(&issuance)
	if err == sql.ErrNoRows {
		return fmt.Errorf("incompatible vault database %s: missing issuance table; do not delete authoritative deployment data: stop the signer and restore a verified compatible backup or use a reviewed migration", path)
	}
	if err != nil {
		return err
	}
	cols, err = tableColumns(db, "issuance")
	if err != nil {
		return fmt.Errorf("incompatible vault database %s: %w", path, err)
	}
	legacy := sameColumns(cols, issuanceColumnsLegacy)
	sealed := sameColumns(cols, issuanceColumns)
	if !legacy && !sealed {
		return fmt.Errorf("incompatible vault database %s: issuance columns %v, want %v; do not delete authoritative deployment data: stop the signer and restore a verified compatible backup or use a reviewed migration", path, cols, issuanceColumns)
	}
	if err := requireSchemaFragments(db, "issuance", []string{
		"state TEXT NOT NULL CHECK (state IN ('reserved', 'vault_signed', 'completed'))",
		"request_psbt TEXT NOT NULL CHECK (length(request_psbt) > 0)",
		"(state = 'reserved' AND vault_psbt IS NULL AND signed_psbt IS NULL)",
		"(state = 'vault_signed' AND vault_psbt IS NOT NULL AND signed_psbt IS NULL)",
		"(state = 'completed' AND vault_psbt IS NOT NULL AND signed_psbt IS NOT NULL)",
		"PRIMARY KEY (vault_id, arkade_sighash)",
	}); err != nil {
		return fmt.Errorf("incompatible vault database %s: issuance constraints: %w; do not delete authoritative deployment data: stop the signer and restore a verified compatible backup or use a reviewed migration", path, err)
	}
	if sealed {
		if err := requireSchemaFragments(db, "issuance", []string{
			"integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32)",
		}); err != nil {
			return fmt.Errorf("incompatible vault database %s: issuance constraints: %w; do not delete authoritative deployment data: stop the signer and restore a verified compatible backup or use a reviewed migration", path, err)
		}
	}
	return nil
}

// MigrateIssuanceIntegrity is the v4→v5 step. It must run only after the
// live record has been verified and a rollback snapshot exists. OpenLedger
// never calls this. An empty pre-MAC issuance table may be rebuilt; any
// unsealed row fails closed.
func (l *Ledger) MigrateIssuanceIntegrity(integrityKey []byte) error {
	if len(integrityKey) != 32 {
		return fmt.Errorf("credential integrity key must be 32 bytes")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	zeroBytes(l.integrityKey)
	l.integrityKey = append([]byte(nil), integrityKey...)
	ver, n, err := schemaMetaState(l.db)
	if err != nil && v4TableExists(l.db) {
		return err
	}
	if v4TableExists(l.db) {
		if err := checkSchemaVersionAt(ver, n, schemaVersionCurrent); err != nil {
			return err
		}
	}
	if err := ensureIssuanceIntegrity(l.db, "issuance"); err != nil {
		return err
	}
	if v4TableExists(l.db) && n == 1 && ver == schemaVersionMultiTenant {
		if _, err := l.db.Exec(`UPDATE schema_meta SET version = ? WHERE version = ?`, schemaVersionIssuanceMAC, schemaVersionMultiTenant); err != nil {
			return fmt.Errorf("issuance mac schema version: %w", err)
		}
	}
	return nil
}

func ensureIssuanceIntegrity(db *sql.DB, path string) error {
	cols, err := tableColumns(db, "issuance")
	if err != nil {
		return fmt.Errorf("incompatible vault database %s: %w", path, err)
	}
	if sameColumns(cols, issuanceColumns) {
		return nil
	}
	if !sameColumns(cols, issuanceColumnsLegacy) {
		return fmt.Errorf("incompatible vault database %s: issuance columns %v, want %v; do not delete authoritative deployment data: stop the signer and restore a verified compatible backup or use a reviewed migration", path, cols, issuanceColumns)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM issuance`).Scan(&n); err != nil {
		return err
	}
	if n != 0 {
		return fmt.Errorf("incompatible vault database %s: unsealed issuance rows exist; do not delete authoritative deployment data: stop the signer and restore a verified compatible backup or use a reviewed migration", path)
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DROP TABLE issuance`); err != nil {
		return fmt.Errorf("issuance mac migrate: %w", err)
	}
	if _, err := tx.Exec(createSealedIssuanceTable); err != nil {
		return fmt.Errorf("issuance mac migrate: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return validateV3CoreSchema(db, path)
}

const createSealedIssuanceTable = `
CREATE TABLE issuance (
  vault_id TEXT NOT NULL,
  arkade_sighash BLOB NOT NULL,
  period_start TEXT NOT NULL,
  recipient_amount INTEGER NOT NULL,
  fee INTEGER NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('reserved', 'vault_signed', 'completed')),
  request_psbt TEXT NOT NULL CHECK (length(request_psbt) > 0),
  vault_psbt TEXT,
  signed_psbt TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32),
  CHECK (
    (state = 'reserved' AND vault_psbt IS NULL AND signed_psbt IS NULL) OR
    (state = 'vault_signed' AND vault_psbt IS NOT NULL AND signed_psbt IS NULL) OR
    (state = 'completed' AND vault_psbt IS NOT NULL AND signed_psbt IS NOT NULL)
  ),
  PRIMARY KEY (vault_id, arkade_sighash)
);
`

func validateCredentialEnvelopeSchema(db *sql.DB, path string) error {
	cols, err := tableColumns(db, "credential_envelope")
	if err != nil {
		return fmt.Errorf("incompatible vault database %s: %w", path, err)
	}
	if !sameColumns(cols, credentialEnvelopeColumns) {
		return fmt.Errorf("incompatible vault database %s: credential_envelope columns %v, want %v; restore a verified backup or use a reviewed migration", path, cols, credentialEnvelopeColumns)
	}
	if err := requireSchemaFragments(db, "credential_envelope", []string{
		"id INTEGER PRIMARY KEY CHECK (id = 1)",
		"version INTEGER NOT NULL CHECK (version = 1)",
		"binding TEXT NOT NULL CHECK (length(binding) > 0 AND length(binding) <= 16384)",
		"nonce BLOB NOT NULL CHECK (length(nonce) = 12)",
		"ciphertext BLOB NOT NULL CHECK (length(ciphertext) = 48)",
		"direct_signature BLOB NOT NULL CHECK (length(direct_signature) = 64)",
		"phone_signature BLOB NOT NULL CHECK (length(phone_signature) = 64)",
		"integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32)",
	}); err != nil {
		return fmt.Errorf("incompatible vault database %s: credential_envelope constraints: %w; restore a verified backup or use a reviewed migration", path, err)
	}
	return nil
}

// MigrateLegacySingleton copies credential id=1 into vault + vault_credential
// as operational-vault-v1 with cosigner_mode=legacy-direct-v0. Forward-only,
// transactional, and idempotent. Verifies the v3 MAC before writing the v4 row.
// New enrollment remains disabled at the HTTP layer.
func (l *Ledger) MigrateLegacySingleton(integrityKey []byte) error {
	if len(integrityKey) != 32 {
		return fmt.Errorf("credential integrity key must be 32 bytes")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := rejectUnsupportedSchemaVersion(l.db); err != nil {
		return err
	}
	tx, err := l.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := ensureMultiTenantSchemaTx(tx); err != nil {
		return err
	}
	if err := migrateLegacySingletonTx(tx, integrityKey); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return requireForeignKeyCheckClean(l.db)
}

func migrateLegacySingletonTx(tx *sql.Tx, integrityKey []byte) error {
	if _, err := tx.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		return err
	}
	ver, n, err := schemaMetaState(tx)
	if err != nil {
		return err
	}
	if n > 1 {
		return fmt.Errorf("schema_meta must contain exactly one version row, have %d", n)
	}
	if n == 1 && ver > schemaVersionCurrent {
		return fmt.Errorf("schema version %d is newer than this binary", ver)
	}
	legacy, err := getCredentialTx(tx)
	if err != nil {
		return err
	}
	if legacy != nil {
		if err := VerifyCredentialIntegrity(legacy, integrityKey); err != nil {
			return fmt.Errorf("legacy credential: %w", err)
		}
		if legacy.VaultID != LegacyFirstVaultID {
			return fmt.Errorf("legacy fallback applies only to %s", LegacyFirstVaultID)
		}
		if err := upsertMigratedLegacyVault(tx, *legacy, integrityKey); err != nil {
			return err
		}
	}
	if n == 0 {
		if _, err := tx.Exec(`INSERT INTO schema_meta (version) VALUES (?)`, schemaVersionMultiTenant); err != nil {
			return err
		}
	}
	return nil
}

func upsertMigratedLegacyVault(tx *sql.Tx, legacy Credential, integrityKey []byte) error {
	rec := vaultRecordFromCredential(legacy)
	if rec.CosignerMode != CosignerModeLegacyDirectV0 {
		return fmt.Errorf("first vault must persist %s", CosignerModeLegacyDirectV0)
	}
	if err := sealVaultRecord(&rec, integrityKey); err != nil {
		return err
	}
	cred := VaultCredential{
		CredentialID: append([]byte(nil), legacy.ID...),
		VaultID:      rec.VaultID,
		WebAuthnP256: append([]byte(nil), legacy.WebAuthnP256...),
		UserHandle:   nil, // historical handle was never stored; do not invent vault_id bytes
		Resident:     false,
	}
	if err := sealVaultCredential(&cred, integrityKey); err != nil {
		return err
	}
	var envelope *CredentialEnvelope
	env, err := getEnvelopeTx(tx)
	if err != nil {
		return err
	}
	if env != nil {
		if err := VerifyCredentialEnvelope(env, legacy.ID, integrityKey); err != nil {
			return fmt.Errorf("legacy envelope: %w", err)
		}
		envelope = env
	}

	existing, err := getVaultTx(tx, rec.VaultID)
	if err != nil {
		return err
	}
	existingCred, err := getVaultCredentialTx(tx, rec.VaultID)
	if err != nil {
		return err
	}
	if existing == nil && existingCred != nil {
		return fmt.Errorf("partial migration: vault_credential without vault")
	}
	if existing == nil {
		if err := insertVaultTx(tx, rec, cred, envelope); err != nil {
			return fmt.Errorf("migrate vault row: %w", err)
		}
		return nil
	}
	if err := verifyVaultRecord(existing, integrityKey); err != nil {
		return fmt.Errorf("existing v4 vault: %w", err)
	}
	if err := vaultRecordsCanonicallyEqual(*existing, rec); err != nil {
		return fmt.Errorf("existing v4 vault does not match the verified v3 descriptor (%v)", err)
	}
	if existingCred == nil {
		if err := insertVaultCredentialTx(tx, cred); err != nil {
			return fmt.Errorf("migrate vault credential: %w", err)
		}
	} else {
		if err := verifyVaultCredential(existingCred, integrityKey); err != nil {
			return fmt.Errorf("existing v4 credential: %w", err)
		}
		if err := vaultCredentialsCanonicallyEqual(*existingCred, cred); err != nil {
			return fmt.Errorf("existing v4 credential does not match the verified v3 descriptor (%v)", err)
		}
	}
	if envelope == nil {
		return nil
	}
	existingEnv, err := getVaultEnvelopeTx(tx, rec.VaultID)
	if err != nil {
		return err
	}
	if existingEnv == nil {
		if err := insertVaultEnvelopeTx(tx, rec.VaultID, *envelope); err != nil {
			return fmt.Errorf("migrate vault envelope: %w", err)
		}
		return nil
	}
	if !envelopesEqual(*existingEnv, *envelope) {
		return fmt.Errorf("existing v4 envelope does not match the verified v3 envelope")
	}
	return nil
}

func getCredentialTx(tx *sql.Tx) (*Credential, error) {
	return loadCredential(tx)
}

func getEnvelopeTx(tx *sql.Tx) (*CredentialEnvelope, error) {
	var envelope CredentialEnvelope
	err := tx.QueryRow(`
SELECT version, binding, nonce, ciphertext, direct_signature, phone_signature, integrity_mac
  FROM credential_envelope WHERE id = 1`).Scan(
		&envelope.Version, &envelope.Binding, &envelope.Nonce, &envelope.Ciphertext,
		&envelope.DirectSig, &envelope.PhoneSig, &envelope.IntegrityMAC,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := validateCredentialEnvelope(envelope); err != nil {
		return nil, err
	}
	return &envelope, nil
}
