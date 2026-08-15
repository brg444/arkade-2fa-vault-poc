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
	if err == nil || !strings.Contains(err.Error(), "stale POC database") {
		t.Fatalf("want stale schema error, got %v", err)
	}
}
