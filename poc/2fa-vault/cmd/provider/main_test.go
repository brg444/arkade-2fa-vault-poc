package main

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/arkade-os/emulator/poc/2fa-vault/internal/deployment"
	"github.com/btcsuite/btcd/btcec/v2"
)

func TestProviderAcceptsOnlyCompressedRegtestOfflinePub(t *testing.T) {
	key, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	encoded := hex.EncodeToString(key.PubKey().SerializeCompressed())
	if _, err := parseCompressedPub(encoded, "offline pubkey"); err != nil {
		t.Fatal(err)
	}
	if _, err := parseCompressedPub(hex.EncodeToString(key.PubKey().SerializeUncompressed()), "offline pubkey"); err == nil {
		t.Fatal("uncompressed offline key accepted")
	}
}

func TestProviderBinaryCannotSelectMutinynetSignerModes(t *testing.T) {
	if err := requireRegtestProvider(deployment.NetworkRegtest); err != nil {
		t.Fatal(err)
	}
	if err := requireRegtestProvider(deployment.NetworkMutinynet); err == nil || !strings.Contains(err.Error(), "cmd/authorizer") {
		t.Fatalf("Mutinynet provider mode accepted: %v", err)
	}
}
