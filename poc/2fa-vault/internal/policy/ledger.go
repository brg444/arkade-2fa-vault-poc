package policy

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/arkade-os/emulator/poc/2fa-vault/internal/webauthn"
	_ "modernc.org/sqlite"
)

const (
	stateReserved  = "reserved"
	stateCompleted = "completed"
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
	if _, err := db.Exec(`PRAGMA busy_timeout = 5000`); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := ensurePOCSchema(db, path); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Ledger{db: db, clock: clock}, nil
}

var credentialColumns = []string{
	"id", "credential_id", "webauthn_p256_compressed", "direct_p256_compressed",
	"rp_id", "origin", "created_at",
	"hot_compressed", "offline_compressed", "provider_base_compressed",
	"tweaked_provider_compressed", "template_version", "policy_version",
	"network", "vault_id", "operational_csv_type", "operational_csv_value",
	"savings_csv_type", "savings_csv_value", "operational_address",
	"operational_script", "savings_address", "savings_script",
}

const createPOCSchema = `
CREATE TABLE credential (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  credential_id BLOB NOT NULL,
  webauthn_p256_compressed BLOB NOT NULL,
  direct_p256_compressed BLOB NOT NULL,
  rp_id TEXT NOT NULL,
  origin TEXT NOT NULL,
  created_at TEXT NOT NULL,
  hot_compressed BLOB NOT NULL,
  offline_compressed BLOB NOT NULL,
  provider_base_compressed BLOB NOT NULL,
  tweaked_provider_compressed BLOB NOT NULL,
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
  savings_script BLOB NOT NULL
);
CREATE TABLE issuance (
  vault_id TEXT NOT NULL,
  arkade_sighash BLOB NOT NULL,
  period_start TEXT NOT NULL,
  recipient_amount INTEGER NOT NULL,
  fee INTEGER NOT NULL,
  state TEXT NOT NULL,
  signed_psbt TEXT,
  created_at TEXT NOT NULL,
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
		return fmt.Errorf("stale POC database %s: credential columns %v, want %v; delete the file and restart", path, cols, credentialColumns)
	}
	var issuance string
	err = db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='issuance'`).Scan(&issuance)
	if err == sql.ErrNoRows {
		return fmt.Errorf("stale POC database %s: missing issuance table; delete the file and restart", path)
	}
	return err
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
	ID           []byte
	WebAuthnP256 []byte
	DirectP256   []byte
	Hot          []byte
	RPID         string
	Origin       string

	Offline             []byte
	ProviderBase        []byte
	TweakedProvider     []byte
	TemplateVersion     string
	PolicyVersion       string
	Network             string
	VaultID             string
	OperationalCSVType  int64
	OperationalCSVValue uint32
	SavingsCSVType      int64
	SavingsCSVValue     uint32
	OperationalAddress  string
	OperationalScript   []byte
	SavingsAddress      string
	SavingsScript       []byte
}

func (l *Ledger) GetCredential() (*Credential, error) {
	var c Credential
	err := l.db.QueryRow(`
SELECT credential_id, webauthn_p256_compressed, direct_p256_compressed, rp_id, origin, hot_compressed,
       offline_compressed, provider_base_compressed, tweaked_provider_compressed,
       template_version, policy_version, network, vault_id,
       operational_csv_type, operational_csv_value, savings_csv_type, savings_csv_value,
       operational_address, operational_script, savings_address, savings_script
  FROM credential WHERE id = 1`).Scan(
		&c.ID, &c.WebAuthnP256, &c.DirectP256, &c.RPID, &c.Origin, &c.Hot,
		&c.Offline, &c.ProviderBase, &c.TweakedProvider,
		&c.TemplateVersion, &c.PolicyVersion, &c.Network, &c.VaultID,
		&c.OperationalCSVType, &c.OperationalCSVValue, &c.SavingsCSVType, &c.SavingsCSVValue,
		&c.OperationalAddress, &c.OperationalScript, &c.SavingsAddress, &c.SavingsScript,
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
	if _, err := webauthn.ParseCompressedP256(c.DirectP256); err != nil {
		return fmt.Errorf("direct p256: %w", err)
	}
	if bytes.Equal(c.WebAuthnP256, c.DirectP256) {
		return fmt.Errorf("direct-auth p256 must be distinct from the webauthn credential p256")
	}
	if c.RPID == "" || c.Origin == "" {
		return fmt.Errorf("rp id and origin required")
	}
	if err := requireCompressedKey(c.Hot, "hot pubkey"); err != nil {
		return err
	}
	if err := requireCompressedKey(c.Offline, "offline pubkey"); err != nil {
		return err
	}
	if err := requireCompressedKey(c.ProviderBase, "provider base pubkey"); err != nil {
		return err
	}
	if err := requireCompressedKey(c.TweakedProvider, "tweaked provider pubkey"); err != nil {
		return err
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
	_, err := l.db.Exec(
		`INSERT INTO credential (
		   id, credential_id, webauthn_p256_compressed, direct_p256_compressed, rp_id, origin, created_at,
		   hot_compressed, offline_compressed, provider_base_compressed, tweaked_provider_compressed,
		   template_version, policy_version, network, vault_id,
		   operational_csv_type, operational_csv_value, savings_csv_type, savings_csv_value,
		   operational_address, operational_script, savings_address, savings_script
		 ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.WebAuthnP256, c.DirectP256, c.RPID, c.Origin, l.clock().UTC().Format(time.RFC3339),
		c.Hot, c.Offline, c.ProviderBase, c.TweakedProvider,
		c.TemplateVersion, c.PolicyVersion, c.Network, c.VaultID,
		c.OperationalCSVType, c.OperationalCSVValue, c.SavingsCSVType, c.SavingsCSVValue,
		c.OperationalAddress, c.OperationalScript, c.SavingsAddress, c.SavingsScript,
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

// SpentInPeriod sums completed+reserved economic outflow (recipient + fee)
// for the UTC day.
func (l *Ledger) SpentInPeriod(ctx context.Context, vaultID, period string) (int64, error) {
	var n sql.NullInt64
	err := l.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(recipient_amount + fee), 0) FROM issuance
		 WHERE vault_id = ? AND period_start = ? AND state IN (?, ?)`,
		vaultID, period, stateReserved, stateCompleted,
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

// AuthorizeFn is the external signer. Issue never holds an uncommitted
// write transaction across this callback.
type AuthorizeFn func(ctx context.Context) (signedPSBT string, err error)

const persistTimeout = 5 * time.Second

// Issue commits a reserved row, then signs, then records completion.
//
// Phase 1 commits the reservation before any external Sign call so a crash
// cannot release budget after a signature has escaped. Phase 2 calls sign.
// Phase 3 persists completed in a second transaction on an internal
// bounded context, independent of client cancellation. After phase 1, any
// ambiguous or post-submit failure stays reserved and blocks a same-digest
// re-sign. Only a failure before that commit may leave no row.
func (l *Ledger) Issue(
	ctx context.Context,
	vaultID string,
	digest []byte,
	recipient, fee, remainingCap int64,
	sign AuthorizeFn,
) (signed string, replay bool, err error) {
	if vaultID == "" {
		return "", false, fmt.Errorf("vault id required")
	}
	if len(digest) != 32 {
		return "", false, fmt.Errorf("digest must be 32 bytes")
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
	if sign == nil {
		return "", false, fmt.Errorf("signer required")
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	stored, replay, err := l.commitReservation(ctx, vaultID, digest, recipient, fee, remainingCap)
	if err != nil {
		return "", false, err
	}
	if replay {
		return stored, true, nil
	}

	signed, err = sign(ctx)
	if err != nil {
		return "", false, err
	}
	if signed == "" {
		return "", false, fmt.Errorf("empty signed response")
	}

	persist, cancel := context.WithTimeout(context.Background(), persistTimeout)
	defer cancel()
	if err := l.commitCompletion(persist, vaultID, digest, signed); err != nil {
		return "", false, err
	}
	if err := ctx.Err(); err != nil {
		return signed, false, err
	}
	return signed, false, nil
}

func (l *Ledger) commitReservation(ctx context.Context, vaultID string, digest []byte, recipient, fee, remainingCap int64) (string, bool, error) {
	conn, err := l.db.Conn(ctx)
	if err != nil {
		return "", false, err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return "", false, err
	}
	commit := false
	defer func() {
		if !commit {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()

	var state string
	var stored sql.NullString
	err = conn.QueryRowContext(ctx,
		`SELECT state, signed_psbt FROM issuance WHERE vault_id = ? AND arkade_sighash = ?`,
		vaultID, digest,
	).Scan(&state, &stored)
	switch {
	case err == nil && state == stateCompleted && stored.Valid:
		if _, err := conn.ExecContext(context.Background(), `COMMIT`); err != nil {
			return "", false, err
		}
		commit = true
		return stored.String, true, nil
	case err == nil:
		if _, err := conn.ExecContext(context.Background(), `COMMIT`); err != nil {
			return "", false, err
		}
		commit = true
		return "", false, fmt.Errorf("issuance %s already %s", hex.EncodeToString(digest), state)
	case err != sql.ErrNoRows:
		return "", false, err
	}

	period := l.PeriodStart()
	var used sql.NullInt64
	if err := conn.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(recipient_amount + fee), 0) FROM issuance
		 WHERE vault_id = ? AND period_start = ? AND state IN (?, ?)`,
		vaultID, period, stateReserved, stateCompleted,
	).Scan(&used); err != nil {
		return "", false, err
	}
	usedAmt := used.Int64
	if !used.Valid || usedAmt < 0 {
		return "", false, fmt.Errorf("period spent invalid")
	}
	need, err := addOutflow(recipient, fee)
	if err != nil {
		return "", false, err
	}
	if usedAmt > remainingCap {
		return "", false, fmt.Errorf("period allowance exceeded")
	}
	if need > remainingCap-usedAmt {
		return "", false, fmt.Errorf("period allowance exceeded")
	}

	if _, err := conn.ExecContext(ctx,
		`INSERT INTO issuance (vault_id, arkade_sighash, period_start, recipient_amount, fee, state, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		vaultID, digest, period, recipient, fee, stateReserved, l.clock().UTC().Format(time.RFC3339),
	); err != nil {
		return "", false, err
	}
	if _, err := conn.ExecContext(context.Background(), `COMMIT`); err != nil {
		return "", false, err
	}
	commit = true
	return "", false, nil
}

func (l *Ledger) commitCompletion(ctx context.Context, vaultID string, digest []byte, signed string) error {
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
		`UPDATE issuance SET state = ?, signed_psbt = ? WHERE vault_id = ? AND arkade_sighash = ? AND state = ?`,
		stateCompleted, signed, vaultID, digest, stateReserved,
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("issuance %s not reserved", hex.EncodeToString(digest))
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return err
	}
	commit = true
	return nil
}
