package policy

import (
	"database/sql"
	"fmt"
	"strings"
)

type colSpec struct {
	Name    string
	Type    string
	NotNull bool
	PK      int
}

type fkSpec struct {
	Table string
	From  string
	To    string
}

type idxSpec struct {
	Name   string
	Unique bool
	Cols   []string
}

func spec(name, ctype string, notNull bool, pk int) colSpec {
	return colSpec{Name: name, Type: ctype, NotNull: notNull, PK: pk}
}

var expectedV4Tables = map[string]struct {
	cols    []colSpec
	fks     []fkSpec
	indexes []idxSpec
}{
	"schema_meta": {
		cols: []colSpec{spec("version", "INTEGER", false, 1)},
	},
	"vault": {
		cols: []colSpec{
			spec("vault_id", "TEXT", true, 1),
			spec("template_version", "TEXT", true, 0),
			spec("policy_version", "TEXT", true, 0),
			spec("network", "TEXT", true, 0),
			spec("rp_id", "TEXT", true, 0),
			spec("origin", "TEXT", true, 0),
			spec("phone_routine_bip340_compressed", "BLOB", true, 0),
			spec("phone_direct_p256_compressed", "BLOB", true, 0),
			spec("external_owner_wallet_compressed", "BLOB", true, 0),
			spec("recovery_key_compressed", "BLOB", true, 0),
			spec("vault_cosigner_base_compressed", "BLOB", true, 0),
			spec("tweaked_vault_cosigner_compressed", "BLOB", true, 0),
			spec("arkade_cosigner_base_compressed", "BLOB", true, 0),
			spec("tweaked_arkade_cosigner_compressed", "BLOB", true, 0),
			spec("arkade_cosigner_origin", "TEXT", true, 0),
			spec("arkade_cosigner_version", "TEXT", true, 0),
			spec("cosigner_mode", "TEXT", true, 0),
			spec("operational_csv_type", "INTEGER", true, 0),
			spec("operational_csv_value", "INTEGER", true, 0),
			spec("savings_csv_type", "INTEGER", true, 0),
			spec("savings_csv_value", "INTEGER", true, 0),
			spec("operational_address", "TEXT", true, 0),
			spec("operational_script", "BLOB", true, 0),
			spec("savings_address", "TEXT", true, 0),
			spec("savings_script", "BLOB", true, 0),
			spec("recipient_dust_sats", "INTEGER", true, 0),
			spec("tx_recipient_cap_sats", "INTEGER", true, 0),
			spec("period_allowance_sats", "INTEGER", true, 0),
			spec("absolute_fee_cap_sats", "INTEGER", true, 0),
			spec("feerate_cap_sat_vb", "INTEGER", true, 0),
			spec("integrity_mac", "BLOB", true, 0),
		},
	},
	"vault_credential": {
		cols: []colSpec{
			spec("credential_id", "BLOB", true, 1),
			spec("vault_id", "TEXT", true, 0),
			spec("webauthn_p256_compressed", "BLOB", true, 0),
			spec("user_handle", "BLOB", false, 0),
			spec("resident", "INTEGER", true, 0),
			spec("integrity_mac", "BLOB", true, 0),
		},
		fks: []fkSpec{{Table: "vault", From: "vault_id", To: "vault_id"}},
		indexes: []idxSpec{
			{Name: "vault_credential_vault", Unique: false, Cols: []string{"vault_id"}},
		},
	},
	"vault_envelope": {
		cols: []colSpec{
			spec("vault_id", "TEXT", true, 1),
			spec("version", "INTEGER", true, 0),
			spec("binding", "TEXT", true, 0),
			spec("nonce", "BLOB", true, 0),
			spec("ciphertext", "BLOB", true, 0),
			spec("direct_signature", "BLOB", true, 0),
			spec("phone_signature", "BLOB", true, 0),
			spec("integrity_mac", "BLOB", true, 0),
		},
		fks: []fkSpec{{Table: "vault", From: "vault_id", To: "vault_id"}},
	},
	"invite": {
		cols: []colSpec{
			spec("token_hash", "BLOB", true, 1),
			spec("expires_at", "TEXT", true, 0),
			spec("consumed_vault_id", "TEXT", false, 0),
			spec("created_at", "TEXT", true, 0),
		},
		fks: []fkSpec{{Table: "vault", From: "consumed_vault_id", To: "vault_id"}},
		indexes: []idxSpec{
			{Name: "", Unique: true, Cols: []string{"consumed_vault_id"}},
		},
	},
	"pending_enrollment": {
		cols: []colSpec{
			spec("handle", "TEXT", true, 1),
			spec("vault_id", "TEXT", true, 0),
			spec("token_hash", "BLOB", true, 0),
			spec("challenge", "BLOB", true, 0),
			spec("expires_at", "TEXT", true, 0),
			spec("created_at", "TEXT", true, 0),
		},
		fks: []fkSpec{{Table: "invite", From: "token_hash", To: "token_hash"}},
		indexes: []idxSpec{
			{Name: "", Unique: true, Cols: []string{"vault_id"}},
			{Name: "", Unique: true, Cols: []string{"token_hash"}},
		},
	},
}

type schemaQuerier interface {
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

func rejectUnsupportedSchemaVersion(q schemaQuerier) error {
	var name string
	err := q.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='schema_meta'`).Scan(&name)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	ver, n, err := schemaMetaState(q)
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	if n != 1 {
		return fmt.Errorf("incompatible vault database: schema_meta must contain exactly one version row, have %d", n)
	}
	if ver > schemaVersionMultiTenant {
		return fmt.Errorf("incompatible vault database: schema version %d is newer than this binary (%d)", ver, schemaVersionMultiTenant)
	}
	if ver != schemaVersionMultiTenant {
		return fmt.Errorf("incompatible vault database: schema_meta version %d, want %d", ver, schemaVersionMultiTenant)
	}
	return nil
}

func v4TableExists(q schemaQuerier) bool {
	var name string
	err := q.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='vault'`).Scan(&name)
	return err == nil
}

func createMultiTenantSchemaOn(q schemaQuerier) error {
	if _, err := q.Exec(createMultiTenantSchema); err != nil {
		return fmt.Errorf("multi-tenant schema: %w", err)
	}
	return nil
}

func validateMultiTenantSchemaOn(q schemaQuerier) error {
	for table, want := range expectedV4Tables {
		got, err := readTableXInfo(q, table)
		if err != nil {
			return fmt.Errorf("incompatible vault database: %s: %w", table, err)
		}
		if err := matchColumns(table, got, want.cols); err != nil {
			return err
		}
		fks, err := readForeignKeys(q, table)
		if err != nil {
			return fmt.Errorf("incompatible vault database: %s foreign keys: %w", table, err)
		}
		if err := matchForeignKeys(table, fks, want.fks); err != nil {
			return err
		}
		idxs, err := readIndexes(q, table)
		if err != nil {
			return fmt.Errorf("incompatible vault database: %s indexes: %w", table, err)
		}
		if err := matchIndexes(table, idxs, want.indexes); err != nil {
			return err
		}
		if err := matchCheckConstraints(q, table); err != nil {
			return err
		}
	}
	return nil
}

var expectedChecks = map[string][]string{
	"vault": {
		"in('legacy-direct-v0','hkdf-sha256-v1')",
		"length(integrity_mac)=32",
	},
	"vault_credential": {
		"in(0,1)",
		"length(integrity_mac)=32",
	},
	"vault_envelope": {
		"version=1",
		"length(binding)>0andlength(binding)<=16384",
		"length(nonce)=12",
		"length(ciphertext)=48",
		"length(direct_signature)=64",
		"length(phone_signature)=64",
		"length(integrity_mac)=32",
	},
	"invite": {
		"length(token_hash)=32",
	},
	"pending_enrollment": {
		"length(token_hash)=32",
	},
}

func matchCheckConstraints(q schemaQuerier, table string) error {
	want := expectedChecks[table]
	if len(want) == 0 {
		return nil
	}
	var sqlText string
	if err := q.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&sqlText); err != nil {
		return fmt.Errorf("incompatible vault database: %s missing create sql", table)
	}
	got := extractNormalizedChecks(sqlText)
	for _, w := range want {
		if !containsNormalizedCheck(got, w) {
			return fmt.Errorf("incompatible vault database: %s missing CHECK %s", table, w)
		}
	}
	return nil
}

func extractNormalizedChecks(createSQL string) []string {
	upper := strings.ToUpper(createSQL)
	var out []string
	for i := 0; i < len(upper); i++ {
		if !strings.HasPrefix(upper[i:], "CHECK") {
			continue
		}
		if i > 0 {
			prev := upper[i-1]
			if (prev >= 'A' && prev <= 'Z') || (prev >= '0' && prev <= '9') || prev == '_' {
				continue
			}
		}
		j := i + 5
		for j < len(createSQL) && (createSQL[j] == ' ' || createSQL[j] == '\n' || createSQL[j] == '\t' || createSQL[j] == '\r') {
			j++
		}
		if j >= len(createSQL) || createSQL[j] != '(' {
			continue
		}
		end, ok := matchParen(createSQL, j)
		if !ok {
			continue
		}
		out = append(out, normalizeCheck(createSQL[j:end+1]))
		i = end
	}
	return out
}

func matchParen(s string, open int) (int, bool) {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return -1, false
}

func normalizeCheck(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c == ' ' || c == '\n' || c == '\t' || c == '\r' {
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func containsNormalizedCheck(got []string, want string) bool {
	for _, g := range got {
		if strings.Contains(g, want) {
			return true
		}
	}
	return false
}

func readTableXInfo(q schemaQuerier, table string) ([]colSpec, error) {
	if !knownSchemaTable(table) {
		return nil, fmt.Errorf("unknown table")
	}
	rows, err := q.Query(`PRAGMA table_xinfo(` + table + `)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cols []colSpec
	for rows.Next() {
		var cid, notnull, pk, hidden int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk, &hidden); err != nil {
			return nil, err
		}
		if hidden != 0 {
			continue
		}
		cols = append(cols, colSpec{
			Name:    name,
			Type:    strings.ToUpper(ctype),
			NotNull: notnull == 1,
			PK:      pk,
		})
	}
	return cols, rows.Err()
}

func matchColumns(table string, got, want []colSpec) error {
	if len(got) != len(want) {
		return fmt.Errorf("incompatible vault database: %s column count %d, want %d; restore a verified backup or use a reviewed migration", table, len(got), len(want))
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.Name != w.Name || g.Type != w.Type || g.PK != w.PK {
			return fmt.Errorf("incompatible vault database: %s column %s type/pk mismatch (got %s pk=%d)", table, w.Name, g.Type, g.PK)
		}
		// PRIMARY KEY columns are reported as notnull=0 by SQLite even when
		// declared NOT NULL (rowid aliases and ordinary PKs).
		if w.PK == 0 && g.NotNull != w.NotNull {
			return fmt.Errorf("incompatible vault database: %s column %s nullability mismatch", table, w.Name)
		}
	}
	return nil
}

func readForeignKeys(q schemaQuerier, table string) ([]fkSpec, error) {
	if !knownSchemaTable(table) {
		return nil, fmt.Errorf("unknown table")
	}
	rows, err := q.Query(`PRAGMA foreign_key_list(` + table + `)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var fks []fkSpec
	for rows.Next() {
		var id, seq int
		var parent, from, to, onUpdate, onDelete, match string
		if err := rows.Scan(&id, &seq, &parent, &from, &to, &onUpdate, &onDelete, &match); err != nil {
			return nil, err
		}
		fks = append(fks, fkSpec{Table: parent, From: from, To: to})
	}
	return fks, rows.Err()
}

func matchForeignKeys(table string, got, want []fkSpec) error {
	if len(got) != len(want) {
		return fmt.Errorf("incompatible vault database: %s foreign key count %d, want %d", table, len(got), len(want))
	}
	used := make([]bool, len(got))
	for _, w := range want {
		found := false
		for i, g := range got {
			if used[i] {
				continue
			}
			if g.Table == w.Table && g.From == w.From && g.To == w.To {
				used[i] = true
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("incompatible vault database: %s missing foreign key %s(%s)->%s(%s)", table, table, w.From, w.Table, w.To)
		}
	}
	return nil
}

func readIndexes(q schemaQuerier, table string) ([]idxSpec, error) {
	if !knownSchemaTable(table) {
		return nil, fmt.Errorf("unknown table")
	}
	rows, err := q.Query(`PRAGMA index_list(` + table + `)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type listed struct {
		name   string
		unique bool
	}
	var listedIdx []listed
	for rows.Next() {
		var seq int
		var name, origin string
		var unique, partial int
		if err := rows.Scan(&seq, &name, &unique, &origin, &partial); err != nil {
			return nil, err
		}
		if partial == 1 {
			continue
		}
		listedIdx = append(listedIdx, listed{name: name, unique: unique == 1})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var out []idxSpec
	for _, idx := range listedIdx {
		ident, err := safeIdent(idx.name)
		if err != nil {
			return nil, err
		}
		info, err := q.Query(`PRAGMA index_info(` + ident + `)`)
		if err != nil {
			return nil, err
		}
		var cols []string
		for info.Next() {
			var seqno, cid int
			var col string
			if err := info.Scan(&seqno, &cid, &col); err != nil {
				info.Close()
				return nil, err
			}
			cols = append(cols, col)
		}
		err = info.Err()
		info.Close()
		if err != nil {
			return nil, err
		}
		out = append(out, idxSpec{Name: idx.name, Unique: idx.unique, Cols: cols})
	}
	return out, nil
}

func safeIdent(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("empty identifier")
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' {
			return "", fmt.Errorf("unsafe identifier")
		}
	}
	return name, nil
}

func matchIndexes(table string, got, want []idxSpec) error {
	for _, w := range want {
		found := false
		for _, g := range got {
			if w.Name != "" && g.Name != w.Name {
				continue
			}
			if g.Unique != w.Unique || !sameStringSlice(g.Cols, w.Cols) {
				continue
			}
			found = true
			break
		}
		if !found {
			return fmt.Errorf("incompatible vault database: %s missing index unique=%v cols=%v", table, w.Unique, w.Cols)
		}
	}
	return nil
}

func sameStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
