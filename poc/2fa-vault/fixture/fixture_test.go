package fixture

import (
	"os"
	"strings"
	"testing"
)

func TestFixtureDoesNotExportOfflinePrivateScalar(t *testing.T) {
	raw, err := os.ReadFile("fixture.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, "OfflinePrivHex") {
		t.Fatal("fixture must not export an offline private scalar")
	}
	if strings.Contains(text, "0000000000000000000000000000000000000000000000000000000000000001") {
		t.Fatal("fixture must not embed secp256k1 scalar 1")
	}
	if OfflinePubHex != "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" {
		t.Fatalf("OfflinePubHex = %s, want the opaque generator fixture", OfflinePubHex)
	}
}
