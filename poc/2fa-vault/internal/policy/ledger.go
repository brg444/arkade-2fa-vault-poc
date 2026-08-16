package policy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/arkade-os/emulator/poc/2fa-vault/internal/webauthn"
	_ "modernc.org/sqlite"
)

const (
	stateReserved    = "reserved"
	stateVaultSigned = "vault_signed"
	stateCompleted   = "completed"
)

// Clock is injectable so UTC day boundaries are testable.
type Clock func() time.Time

// Ledger is the SQLite issuance store.
type Ledger struct {
	db    *sql.DB
	clock Clock
	mu    sync.Mutex // extra process-local serialization around the SQL tx
}

// OpenLedger opens (or creates) the SQLite file.
func OpenLedger(path string, clock Clock) (*Ledger, error) {
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{
		`PRAGMA busy_timeout = 5000`,
		// The policy reservation must reach durable storage before VaultCosigner
		// use. Pin this explicitly instead of inheriting a driver/default mode.
		`PRAGMA synchronous = FULL`,
	} {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	if err := ensurePOCSchema(db, path); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Ledger{db: db, clock: clock}, nil
}

var credentialColumns = []string{
	"id", "credential_id", "webauthn_p256_compressed", "phone_direct_p256_compressed",
	"rp_id", "origin",
	"phone_routine_bip340_compressed", "external_owner_wallet_compressed",
	"recovery_key_compressed", "vault_cosigner_base_compressed",
	"tweaked_vault_cosigner_compressed", "arkade_cosigner_base_compressed",
	"tweaked_arkade_cosigner_compressed", "arkade_cosigner_origin",
	"arkade_cosigner_version", "template_version", "policy_version",
	"network", "vault_id", "operational_csv_type", "operational_csv_value",
	"savings_csv_type", "savings_csv_value", "operational_address",
	"operational_script", "savings_address", "savings_script",
	"recipient_dust_sats", "tx_recipient_cap_sats", "period_allowance_sats",
	"absolute_fee_cap_sats", "feerate_cap_sat_vb", "integrity_mac",
}

var issuanceColumns = []string{
	"vault_id", "arkade_sighash", "period_start", "recipient_amount", "fee",
	"state", "request_psbt", "vault_psbt", "signed_psbt", "created_at", "updated_at",
}

const createPOCSchema = `
CREATE TABLE credential (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  credential_id BLOB NOT NULL,
  webauthn_p256_compressed BLOB NOT NULL,
  phone_direct_p256_compressed BLOB NOT NULL,
  rp_id TEXT NOT NULL,
  origin TEXT NOT NULL,
  phone_routine_bip340_compressed BLOB NOT NULL,
  external_owner_wallet_compressed BLOB NOT NULL,
  recovery_key_compressed BLOB NOT NULL,
  vault_cosigner_base_compressed BLOB NOT NULL,
  tweaked_vault_cosigner_compressed BLOB NOT NULL,
  arkade_cosigner_base_compressed BLOB NOT NULL,
  tweaked_arkade_cosigner_compressed BLOB NOT NULL,
  arkade_cosigner_origin TEXT NOT NULL,
  arkade_cosigner_version TEXT NOT NULL,
  template_version TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  network TEXT NOT NULL,
  vault_id TEXT NOT NULL,
  operational_csv_type INTEGER NOT NULL,
  operational_csv_value INTEGER NOT NULL,
  savings_csv_type INTEGER NOT NULL,
  savings_csv_value INTEGER NOT NULL,
  operational_address TEXT NOT NULL,
  operational_script BLOB NOT NULL,
  savings_address TEXT NOT NULL,
  savings_script BLOB NOT NULL,
  recipient_dust_sats INTEGER NOT NULL,
  tx_recipient_cap_sats INTEGER NOT NULL,
  period_allowance_sats INTEGER NOT NULL,
  absolute_fee_cap_sats INTEGER NOT NULL,
  feerate_cap_sat_vb INTEGER NOT NULL,
  integrity_mac BLOB NOT NULL
);
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
  CHECK (
    (state = 'reserved' AND vault_psbt IS NULL AND signed_psbt IS NULL) OR
    (state = 'vault_signed' AND vault_psbt IS NOT NULL AND signed_psbt IS NULL) OR
    (state = 'completed' AND vault_psbt IS NOT NULL AND signed_psbt IS NOT NULL)
  ),
  PRIMARY KEY (vault_id, arkade_sighash)
);
`

func ensurePOCSchema(db *sql.DB, path string) error {
	var table string
	err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='credential'`).Scan(&table)
	switch {
	case err == sql.ErrNoRows:
		if _, err := db.Exec(createPOCSchema); err != nil {
			return err
		}
		return nil
	case err != nil:
		return err
	}
	cols, err := tableColumns(db, "credential")
	if err != nil {
		return err
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
		return err
	}
	if !sameColumns(cols, issuanceColumns) {
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
	return nil
}

func requireSchemaFragments(db *sql.DB, table string, fragments []string) error {
	if table != "credential" && table != "issuance" {
		return fmt.Errorf("unknown table")
	}
	var schema string
	if err := db.QueryRow(
		`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?`, table,
	).Scan(&schema); err != nil {
		return err
	}
	for _, fragment := range fragments {
		if !strings.Contains(schema, fragment) {
			return fmt.Errorf("missing required %q", fragment)
		}
	}
	return nil
}

func tableColumns(db *sql.DB, table string) ([]string, error) {
	if table != "credential" && table != "issuance" {
		return nil, fmt.Errorf("unknown table")
	}
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		cols = append(cols, name)
	}
	return cols, rows.Err()
}

func sameColumns(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	index := make(map[string]struct{}, len(want))
	for _, w := range want {
		index[w] = struct{}{}
	}
	for _, g := range got {
		if _, ok := index[g]; !ok {
			return false
		}
	}
	return true
}

func (l *Ledger) Close() error { return l.db.Close() }

// PeriodStart is the UTC date of now.
func (l *Ledger) PeriodStart() string {
	return l.clock().UTC().Format("2006-01-02")
}

// Credential is the one-shot enrolled passkey plus the immutable vault descriptor.
type Credential struct {
	ID                  []byte
	WebAuthnP256        []byte
	PhoneDirectP256     []byte
	PhoneRoutineBIP340  []byte
	ExternalOwnerWallet []byte
	RPID                string
	Origin              string

	RecoveryKey           []byte
	VaultCosignerBase     []byte
	TweakedVaultCosigner  []byte
	ArkadeCosignerBase    []byte
	TweakedArkadeCosigner []byte
	ArkadeCosignerOrigin  string
	ArkadeCosignerVersion string
	TemplateVersion       string
	PolicyVersion         string
	Network               string
	VaultID               string
	OperationalCSVType    int64
	OperationalCSVValue   uint32
	SavingsCSVType        int64
	SavingsCSVValue       uint32
	OperationalAddress    string
	OperationalScript     []byte
	SavingsAddress        string
	SavingsScript         []byte
	RecipientDustSats     int64
	TxRecipientCapSats    int64
	PeriodAllowanceSats   int64
	AbsoluteFeeCapSats    int64
	FeerateCapSatPerV     int64
	IntegrityMAC          []byte
}

const credentialIntegrityDomain = "arkade-2fa-vault/credential-record/v3"

// SealCredential authenticates every policy/descriptor field in Credential.
// The MAC key is derived and held by the key-owning authorizer; it is never
// persisted beside this record. IntegrityMAC itself is deliberately outside
// the canonical payload.
func SealCredential(c *Credential, key []byte) error {
	if c == nil {
		return fmt.Errorf("credential required")
	}
	mac, err := credentialMAC(*c, key)
	if err != nil {
		return err
	}
	c.IntegrityMAC = mac
	return nil
}

// VerifyCredentialIntegrity rejects a missing, malformed, or modified record
// before any persisted key or descriptor field is used by the authorizer.
func VerifyCredentialIntegrity(c *Credential, key []byte) error {
	if c == nil || len(c.IntegrityMAC) != sha256.Size {
		return fmt.Errorf("credential integrity MAC missing or malformed")
	}
	want, err := credentialMAC(*c, key)
	if err != nil {
		return err
	}
	defer zeroBytes(want)
	if !hmac.Equal(c.IntegrityMAC, want) {
		return fmt.Errorf("credential integrity MAC mismatch")
	}
	return nil
}

func credentialMAC(c Credential, key []byte) ([]byte, error) {
	if len(key) != sha256.Size {
		return nil, fmt.Errorf("credential integrity key must be 32 bytes")
	}
	payload, err := canonicalCredential(c)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(payload)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	return mac.Sum(nil), nil
}

func canonicalCredential(c Credential) ([]byte, error) {
	out := make([]byte, 0, 1024)
	var err error
	out, err = appendCredentialField(out, []byte(credentialIntegrityDomain))
	if err != nil {
		return nil, err
	}
	out = binary.LittleEndian.AppendUint32(out, 3) // canonical record version
	fields := [][]byte{
		c.ID, c.WebAuthnP256, c.PhoneDirectP256, c.PhoneRoutineBIP340,
		c.ExternalOwnerWallet, []byte(c.RPID), []byte(c.Origin),
		c.RecoveryKey, c.VaultCosignerBase,
		c.TweakedVaultCosigner, c.ArkadeCosignerBase, c.TweakedArkadeCosigner,
		[]byte(c.ArkadeCosignerOrigin), []byte(c.ArkadeCosignerVersion),
		[]byte(c.TemplateVersion), []byte(c.PolicyVersion),
		[]byte(c.Network), []byte(c.VaultID),
	}
	for _, field := range fields {
		out, err = appendCredentialField(out, field)
		if err != nil {
			zeroBytes(out)
			return nil, err
		}
	}
	out = binary.LittleEndian.AppendUint64(out, uint64(c.OperationalCSVType))
	out = binary.LittleEndian.AppendUint32(out, c.OperationalCSVValue)
	out = binary.LittleEndian.AppendUint64(out, uint64(c.SavingsCSVType))
	out = binary.LittleEndian.AppendUint32(out, c.SavingsCSVValue)
	out = binary.LittleEndian.AppendUint64(out, uint64(c.RecipientDustSats))
	out = binary.LittleEndian.AppendUint64(out, uint64(c.TxRecipientCapSats))
	out = binary.LittleEndian.AppendUint64(out, uint64(c.PeriodAllowanceSats))
	out = binary.LittleEndian.AppendUint64(out, uint64(c.AbsoluteFeeCapSats))
	out = binary.LittleEndian.AppendUint64(out, uint64(c.FeerateCapSatPerV))
	for _, field := range [][]byte{
		[]byte(c.OperationalAddress), c.OperationalScript,
		[]byte(c.SavingsAddress), c.SavingsScript,
	} {
		out, err = appendCredentialField(out, field)
		if err != nil {
			zeroBytes(out)
			return nil, err
		}
	}
	return out, nil
}

func appendCredentialField(dst, field []byte) ([]byte, error) {
	if uint64(len(field)) > uint64(^uint32(0)) {
		return dst, fmt.Errorf("credential field too large")
	}
	dst = binary.LittleEndian.AppendUint32(dst, uint32(len(field)))
	return append(dst, field...), nil
}

func zeroBytes(raw []byte) {
	for i := range raw {
		raw[i] = 0
	}
}

func (l *Ledger) GetCredential() (*Credential, error) {
	var c Credential
	err := l.db.QueryRow(`
SELECT credential_id, webauthn_p256_compressed, phone_direct_p256_compressed, rp_id, origin, phone_routine_bip340_compressed,
       external_owner_wallet_compressed,
       recovery_key_compressed, vault_cosigner_base_compressed, tweaked_vault_cosigner_compressed,
       arkade_cosigner_base_compressed, tweaked_arkade_cosigner_compressed, arkade_cosigner_origin, arkade_cosigner_version,
       template_version, policy_version, network, vault_id,
       operational_csv_type, operational_csv_value, savings_csv_type, savings_csv_value,
       operational_address, operational_script, savings_address, savings_script,
       recipient_dust_sats, tx_recipient_cap_sats, period_allowance_sats,
       absolute_fee_cap_sats, feerate_cap_sat_vb, integrity_mac
  FROM credential WHERE id = 1`).Scan(
		&c.ID, &c.WebAuthnP256, &c.PhoneDirectP256, &c.RPID, &c.Origin, &c.PhoneRoutineBIP340,
		&c.ExternalOwnerWallet,
		&c.RecoveryKey, &c.VaultCosignerBase, &c.TweakedVaultCosigner,
		&c.ArkadeCosignerBase, &c.TweakedArkadeCosigner, &c.ArkadeCosignerOrigin, &c.ArkadeCosignerVersion,
		&c.TemplateVersion, &c.PolicyVersion, &c.Network, &c.VaultID,
		&c.OperationalCSVType, &c.OperationalCSVValue, &c.SavingsCSVType, &c.SavingsCSVValue,
		&c.OperationalAddress, &c.OperationalScript, &c.SavingsAddress, &c.SavingsScript,
		&c.RecipientDustSats, &c.TxRecipientCapSats, &c.PeriodAllowanceSats,
		&c.AbsoluteFeeCapSats, &c.FeerateCapSatPerV, &c.IntegrityMAC,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (l *Ledger) Enroll(c Credential) error {
	if len(c.ID) == 0 {
		return fmt.Errorf("credential id required")
	}
	if _, err := webauthn.ParseCompressedP256(c.WebAuthnP256); err != nil {
		return fmt.Errorf("webauthn p256: %w", err)
	}
	if _, err := webauthn.ParseCompressedP256(c.PhoneDirectP256); err != nil {
		return fmt.Errorf("direct p256: %w", err)
	}
	if bytes.Equal(c.WebAuthnP256, c.PhoneDirectP256) {
		return fmt.Errorf("direct-auth p256 must be distinct from the webauthn credential p256")
	}
	if c.RPID == "" || c.Origin == "" {
		return fmt.Errorf("rp id and origin required")
	}
	if err := requireCompressedKey(c.PhoneRoutineBIP340, "phone routine BIP340 pubkey"); err != nil {
		return err
	}
	if err := requireCompressedKey(c.ExternalOwnerWallet, "external owner wallet pubkey"); err != nil {
		return err
	}
	if err := requireCompressedKey(c.RecoveryKey, "recovery key pubkey"); err != nil {
		return err
	}
	if err := requireCompressedKey(c.VaultCosignerBase, "vault cosigner base pubkey"); err != nil {
		return err
	}
	if err := requireCompressedKey(c.TweakedVaultCosigner, "tweaked vault cosigner pubkey"); err != nil {
		return err
	}
	if err := requireCompressedKey(c.ArkadeCosignerBase, "arkade cosigner base pubkey"); err != nil {
		return err
	}
	if err := requireCompressedKey(c.TweakedArkadeCosigner, "tweaked arkade cosigner pubkey"); err != nil {
		return err
	}
	if err := requireIndependentXOnlyKeys(
		c.PhoneRoutineBIP340, c.ExternalOwnerWallet, c.RecoveryKey,
		c.VaultCosignerBase, c.TweakedVaultCosigner,
		c.ArkadeCosignerBase, c.TweakedArkadeCosigner,
	); err != nil {
		return err
	}
	if c.Network != "regtest" && (c.ArkadeCosignerOrigin == "" || c.ArkadeCosignerVersion == "") {
		return fmt.Errorf("public arkade cosigner origin and version required")
	}
	if c.TemplateVersion == "" || c.PolicyVersion == "" || c.Network == "" || c.VaultID == "" {
		return fmt.Errorf("template, policy, network and vault id required")
	}
	if c.OperationalCSVValue == 0 || c.SavingsCSVValue == 0 {
		return fmt.Errorf("csv values required")
	}
	if c.OperationalAddress == "" || c.SavingsAddress == "" ||
		len(c.OperationalScript) == 0 || len(c.SavingsScript) == 0 {
		return fmt.Errorf("vault addresses and scripts required")
	}
	if c.RecipientDustSats <= 0 || c.TxRecipientCapSats < c.RecipientDustSats ||
		c.PeriodAllowanceSats <= 0 || c.AbsoluteFeeCapSats < 0 || c.FeerateCapSatPerV <= 0 {
		return fmt.Errorf("invalid persisted economic policy")
	}
	if len(c.IntegrityMAC) != sha256.Size {
		return fmt.Errorf("credential integrity MAC must be 32 bytes")
	}
	_, err := l.db.Exec(
		`INSERT INTO credential (
		   id, credential_id, webauthn_p256_compressed, phone_direct_p256_compressed, rp_id, origin,
		   phone_routine_bip340_compressed, external_owner_wallet_compressed,
		   recovery_key_compressed, vault_cosigner_base_compressed, tweaked_vault_cosigner_compressed,
		   arkade_cosigner_base_compressed, tweaked_arkade_cosigner_compressed, arkade_cosigner_origin, arkade_cosigner_version,
		   template_version, policy_version, network, vault_id,
		   operational_csv_type, operational_csv_value, savings_csv_type, savings_csv_value,
		   operational_address, operational_script, savings_address, savings_script,
		   recipient_dust_sats, tx_recipient_cap_sats, period_allowance_sats,
		   absolute_fee_cap_sats, feerate_cap_sat_vb, integrity_mac
		 ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.WebAuthnP256, c.PhoneDirectP256, c.RPID, c.Origin,
		c.PhoneRoutineBIP340, c.ExternalOwnerWallet, c.RecoveryKey,
		c.VaultCosignerBase, c.TweakedVaultCosigner,
		c.ArkadeCosignerBase, c.TweakedArkadeCosigner, c.ArkadeCosignerOrigin, c.ArkadeCosignerVersion,
		c.TemplateVersion, c.PolicyVersion, c.Network, c.VaultID,
		c.OperationalCSVType, c.OperationalCSVValue, c.SavingsCSVType, c.SavingsCSVValue,
		c.OperationalAddress, c.OperationalScript, c.SavingsAddress, c.SavingsScript,
		c.RecipientDustSats, c.TxRecipientCapSats, c.PeriodAllowanceSats,
		c.AbsoluteFeeCapSats, c.FeerateCapSatPerV, c.IntegrityMAC,
	)
	if err != nil {
		return fmt.Errorf("enrollment locked or failed: %w", err)
	}
	return nil
}

func addOutflow(recipient, fee int64) (int64, error) {
	if recipient < 0 || fee < 0 {
		return 0, fmt.Errorf("negative outflow")
	}
	if fee > 0 && recipient > (1<<63-1)-fee {
		return 0, fmt.Errorf("recipient+fee overflow")
	}
	return recipient + fee, nil
}

func requireCompressedKey(b []byte, name string) error {
	if len(b) != 33 || (b[0] != 0x02 && b[0] != 0x03) {
		return fmt.Errorf("%s must be 33-byte compressed secp256k1", name)
	}
	return nil
}

func requireIndependentXOnlyKeys(keys ...[]byte) error {
	for i := range keys {
		for j := i + 1; j < len(keys); j++ {
			// requireCompressedKey has already established the 33-byte SEC
			// encoding. The remaining 32 bytes are the Taproot identity, so
			// opposite compressed parities must also be rejected.
			if bytes.Equal(keys[i][1:], keys[j][1:]) {
				return fmt.Errorf("secp256k1 key roles must be independent by x-only identity")
			}
		}
	}
	return nil
}

// SpentInPeriod sums completed+reserved economic outflow (recipient + fee)
// for the UTC day.
func (l *Ledger) SpentInPeriod(ctx context.Context, vaultID, period string) (int64, error) {
	var n sql.NullInt64
	err := l.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(recipient_amount + fee), 0) FROM issuance
		 WHERE vault_id = ? AND period_start = ? AND state IN (?, ?, ?)`,
		vaultID, period, stateReserved, stateVaultSigned, stateCompleted,
	).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n.Int64, nil
}

// Completed returns the stored signed PSBT for an exact digest, if any.
func (l *Ledger) Completed(ctx context.Context, vaultID string, digest []byte) (string, bool, error) {
	var out sql.NullString
	var state string
	err := l.db.QueryRowContext(ctx,
		`SELECT state, signed_psbt FROM issuance WHERE vault_id = ? AND arkade_sighash = ?`,
		vaultID, digest,
	).Scan(&state, &out)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if state == stateCompleted && out.Valid {
		return out.String, true, nil
	}
	return "", false, nil
}

// AuthorizeFn is the legacy one-stage external signer. Issue retains its
// conservative no-retry semantics for an ambiguous failure after reservation.
type AuthorizeFn func(ctx context.Context) (signedPSBT string, err error)

// SequentialAuthorizeFn transforms one exact persisted PSBT stage into the
// next. The VaultCosigner and ArkadeCosigner stages use the same type, but are
// persisted separately so an ambiguous public timeout never causes private-key reuse.
type SequentialAuthorizeFn func(ctx context.Context, storedPSBT string) (nextPSBT string, err error)

const persistTimeout = 5 * time.Second

// Issue preserves the one-stage API for the regtest/external-signer tests. A
// reserved legacy issuance never retries the ambiguous signer callback.
func (l *Ledger) Issue(
	ctx context.Context,
	vaultID string,
	digest []byte,
	recipient, fee, remainingCap int64,
	sign AuthorizeFn,
) (signed string, replay bool, err error) {
	if sign == nil {
		return "", false, fmt.Errorf("signer required")
	}
	request := "legacy-external-signer:" + hex.EncodeToString(digest)
	return l.issueSequential(
		ctx, vaultID, digest, request, recipient, fee, remainingCap, false,
		func(ctx context.Context, _ string) (string, error) { return sign(ctx) },
		func(_ context.Context, vaultPSBT string) (string, error) { return vaultPSBT, nil },
	)
}

// IssueSequential durably binds an exact normalized client PSBT, reserves its
// allowance, persists the private VaultCosigner signature, and only then
// dispatches that stored PSBT to the public ArkadeCosigner. An exact retry may resume the
// private in-process stage after a crash, or the public stage after any
// ambiguous timeout, but it can never replace the bound request or spend a
// second allowance reservation.
func (l *Ledger) IssueSequential(
	ctx context.Context,
	vaultID string,
	digest []byte,
	requestPSBT string,
	recipient, fee, remainingCap int64,
	vaultSign, arkadeSign SequentialAuthorizeFn,
) (signed string, replay bool, err error) {
	if vaultSign == nil || arkadeSign == nil {
		return "", false, fmt.Errorf("vault and arkade cosigners required")
	}
	return l.issueSequential(
		ctx, vaultID, digest, requestPSBT, recipient, fee, remainingCap, true,
		vaultSign, arkadeSign,
	)
}

type issuanceStage struct {
	state       string
	requestPSBT string
	vaultPSBT   string
	signedPSBT  string
	created     bool
}

func (l *Ledger) issueSequential(
	ctx context.Context,
	vaultID string,
	digest []byte,
	requestPSBT string,
	recipient, fee, remainingCap int64,
	resumeReserved bool,
	vaultSign, arkadeSign SequentialAuthorizeFn,
) (signed string, replay bool, err error) {
	if vaultID == "" {
		return "", false, fmt.Errorf("vault id required")
	}
	if len(digest) != 32 {
		return "", false, fmt.Errorf("digest must be 32 bytes")
	}
	if requestPSBT == "" {
		return "", false, fmt.Errorf("exact request PSBT required")
	}
	if recipient <= 0 {
		return "", false, fmt.Errorf("recipient amount required")
	}
	if fee < 0 {
		return "", false, fmt.Errorf("negative fee")
	}
	if remainingCap < 0 {
		return "", false, fmt.Errorf("negative allowance")
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	stage, err := l.commitReservation(ctx, vaultID, digest, requestPSBT, recipient, fee, remainingCap)
	if err != nil {
		return "", false, err
	}
	if stage.state == stateCompleted {
		return stage.signedPSBT, true, nil
	}
	if stage.state == stateReserved {
		if !stage.created && !resumeReserved {
			return "", false, fmt.Errorf("issuance %s already reserved after an ambiguous signer attempt", hex.EncodeToString(digest))
		}
		vaultPSBT, err := vaultSign(ctx, stage.requestPSBT)
		if err != nil {
			return "", false, err
		}
		if vaultPSBT == "" {
			return "", false, fmt.Errorf("empty private-signed response")
		}
		persist, cancel := context.WithTimeout(context.Background(), persistTimeout)
		err = l.commitVaultSigned(persist, vaultID, digest, vaultPSBT)
		cancel()
		if err != nil {
			return "", false, err
		}
		stage.state = stateVaultSigned
		stage.vaultPSBT = vaultPSBT
	}
	if stage.state != stateVaultSigned || stage.vaultPSBT == "" {
		return "", false, fmt.Errorf("issuance %s has invalid signing state", hex.EncodeToString(digest))
	}
	signed, err = arkadeSign(ctx, stage.vaultPSBT)
	if err != nil {
		return "", false, err
	}
	if signed == "" {
		return "", false, fmt.Errorf("empty public-signed response")
	}

	persist, cancel := context.WithTimeout(context.Background(), persistTimeout)
	err = l.commitCompletion(persist, vaultID, digest, signed)
	cancel()
	if err != nil {
		return "", false, err
	}
	if err := ctx.Err(); err != nil {
		return signed, false, err
	}
	return signed, false, nil
}

func (l *Ledger) commitReservation(
	ctx context.Context,
	vaultID string,
	digest []byte,
	requestPSBT string,
	recipient, fee, remainingCap int64,
) (issuanceStage, error) {
	conn, err := l.db.Conn(ctx)
	if err != nil {
		return issuanceStage{}, err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return issuanceStage{}, err
	}
	commit := false
	defer func() {
		if !commit {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()

	var stage issuanceStage
	var vaultSigned, signed sql.NullString
	var storedRecipient, storedFee int64
	err = conn.QueryRowContext(ctx,
		`SELECT state, request_psbt, vault_psbt, signed_psbt, recipient_amount, fee
		   FROM issuance WHERE vault_id = ? AND arkade_sighash = ?`,
		vaultID, digest,
	).Scan(&stage.state, &stage.requestPSBT, &vaultSigned, &signed, &storedRecipient, &storedFee)
	if err == nil {
		if stage.requestPSBT != requestPSBT || storedRecipient != recipient || storedFee != fee {
			return issuanceStage{}, fmt.Errorf("issuance %s is already bound to a different exact request", hex.EncodeToString(digest))
		}
		if vaultSigned.Valid {
			stage.vaultPSBT = vaultSigned.String
		}
		if signed.Valid {
			stage.signedPSBT = signed.String
		}
		if err := validateIssuanceStage(stage); err != nil {
			return issuanceStage{}, err
		}
		if _, err := conn.ExecContext(context.Background(), `COMMIT`); err != nil {
			return issuanceStage{}, err
		}
		commit = true
		return stage, nil
	}
	if err != sql.ErrNoRows {
		return issuanceStage{}, err
	}

	period := l.PeriodStart()
	var used sql.NullInt64
	if err := conn.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(recipient_amount + fee), 0) FROM issuance
		 WHERE vault_id = ? AND period_start = ? AND state IN (?, ?, ?)`,
		vaultID, period, stateReserved, stateVaultSigned, stateCompleted,
	).Scan(&used); err != nil {
		return issuanceStage{}, err
	}
	usedAmt := used.Int64
	if !used.Valid || usedAmt < 0 {
		return issuanceStage{}, fmt.Errorf("period spent invalid")
	}
	need, err := addOutflow(recipient, fee)
	if err != nil {
		return issuanceStage{}, err
	}
	if usedAmt > remainingCap {
		return issuanceStage{}, fmt.Errorf("period allowance exceeded")
	}
	if need > remainingCap-usedAmt {
		return issuanceStage{}, fmt.Errorf("period allowance exceeded")
	}

	now := l.clock().UTC().Format(time.RFC3339)
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO issuance (
		   vault_id, arkade_sighash, period_start, recipient_amount, fee, state,
		   request_psbt, created_at, updated_at
		 ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		vaultID, digest, period, recipient, fee, stateReserved, requestPSBT, now, now,
	); err != nil {
		return issuanceStage{}, err
	}
	if _, err := conn.ExecContext(context.Background(), `COMMIT`); err != nil {
		return issuanceStage{}, err
	}
	commit = true
	return issuanceStage{state: stateReserved, requestPSBT: requestPSBT, created: true}, nil
}

func validateIssuanceStage(stage issuanceStage) error {
	switch stage.state {
	case stateReserved:
		if stage.requestPSBT == "" || stage.vaultPSBT != "" || stage.signedPSBT != "" {
			return fmt.Errorf("reserved issuance has inconsistent persisted signing data")
		}
	case stateVaultSigned:
		if stage.requestPSBT == "" || stage.vaultPSBT == "" || stage.signedPSBT != "" {
			return fmt.Errorf("vault-signed issuance has inconsistent persisted signing data")
		}
	case stateCompleted:
		if stage.requestPSBT == "" || stage.vaultPSBT == "" || stage.signedPSBT == "" {
			return fmt.Errorf("completed issuance has inconsistent persisted signing data")
		}
	default:
		return fmt.Errorf("unknown issuance state %q", stage.state)
	}
	return nil
}

func (l *Ledger) commitVaultSigned(ctx context.Context, vaultID string, digest []byte, vaultPSBT string) error {
	return l.commitSigningStage(
		ctx, vaultID, digest, stateReserved, stateVaultSigned,
		"vault_psbt", vaultPSBT,
	)
}

func (l *Ledger) commitCompletion(ctx context.Context, vaultID string, digest []byte, signed string) error {
	return l.commitSigningStage(
		ctx, vaultID, digest, stateVaultSigned, stateCompleted,
		"signed_psbt", signed,
	)
}

func (l *Ledger) commitSigningStage(
	ctx context.Context,
	vaultID string,
	digest []byte,
	wantState, nextState, column, value string,
) error {
	if column != "vault_psbt" && column != "signed_psbt" {
		return fmt.Errorf("invalid signing-stage column")
	}
	conn, err := l.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return err
	}
	commit := false
	defer func() {
		if !commit {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()
	res, err := conn.ExecContext(ctx,
		`UPDATE issuance SET state = ?, `+column+` = ?, updated_at = ?
		 WHERE vault_id = ? AND arkade_sighash = ? AND state = ?`,
		nextState, value, l.clock().UTC().Format(time.RFC3339), vaultID, digest, wantState,
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("issuance %s is not in required state %s", hex.EncodeToString(digest), wantState)
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return err
	}
	commit = true
	return nil
}
