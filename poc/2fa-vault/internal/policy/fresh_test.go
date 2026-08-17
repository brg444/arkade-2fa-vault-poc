package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRefuseLegacyDatabaseAllowsMissingAndEmpty(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.sqlite")
	if err := RefuseLegacyDatabase(missing); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(t.TempDir(), "empty.sqlite")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RefuseLegacyDatabase(empty); err != nil {
		t.Fatal(err)
	}
}

func TestRefuseLegacyDatabaseRejectsSingletonCredential(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.sqlite")
	led, err := OpenLedger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := led.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	if err := led.Enroll(validCredential(0x71)); err != nil {
		t.Fatal(err)
	}
	if err := led.Close(); err != nil {
		t.Fatal(err)
	}
	err = RefuseLegacyDatabase(path)
	if err == nil || !strings.Contains(err.Error(), "legacy credential") {
		t.Fatalf("legacy credential accepted: %v", err)
	}
}
