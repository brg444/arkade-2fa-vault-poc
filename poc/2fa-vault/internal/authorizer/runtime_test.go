package authorizer

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arkade-os/emulator/poc/2fa-vault/fixture"
	"github.com/arkade-os/emulator/poc/2fa-vault/internal/deployment"
	"github.com/arkade-os/emulator/poc/2fa-vault/internal/provider"
	"github.com/arkade-os/emulator/poc/2fa-vault/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
)

type stubPublisher struct{}

func (stubPublisher) Broadcast(context.Context, []byte) (string, error) {
	return "", nil
}

func (stubPublisher) Lookup(context.Context, string) (int64, bool, error) {
	return 0, false, nil
}

type stubEmulatorSigner struct{}

func (stubEmulatorSigner) Sign(context.Context, *psbt.Packet) (*psbt.Packet, error) {
	return nil, errors.New("stub public signer must not be called")
}

func TestLoadProviderKeyRejectsNormalizedAndOutOfRangeScalars(t *testing.T) {
	order := btcec.S256().N
	orderMinusOne := new(big.Int).Sub(new(big.Int).Set(order), big.NewInt(1))
	orderPlusOne := new(big.Int).Add(new(big.Int).Set(order), big.NewInt(1))
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "zero", raw: make([]byte, 32)},
		{name: "curve order", raw: order.FillBytes(make([]byte, 32))},
		{name: "curve order plus one", raw: orderPlusOne.FillBytes(make([]byte, 32))},
		{name: "known generator fixture", raw: append(make([]byte, 31), 1)},
		{name: "negated generator fixture", raw: orderMinusOne.FillBytes(make([]byte, 32))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "provider-key")
			if err := os.WriteFile(path, []byte(hex.EncodeToString(test.raw)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadProviderKey(path); err == nil {
				t.Fatal("unsafe provider scalar accepted")
			}
		})
	}

	valid, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "provider-key")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(valid.Serialize())), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadProviderKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.PubKey().IsEqual(valid.PubKey()) {
		t.Fatal("loaded provider key changed")
	}
	overlong := filepath.Join(t.TempDir(), "provider-key")
	if err := os.WriteFile(overlong, []byte(hex.EncodeToString(valid.Serialize())+"  ignored"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProviderKey(overlong); err == nil {
		t.Fatal("overlong file with a valid key prefix was accepted")
	}
}

func TestCredentialIntegrityKeyUsesDomainSeparatedHKDF(t *testing.T) {
	first, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	second, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	a, err := deriveCredentialIntegrityKey(first)
	if err != nil {
		t.Fatal(err)
	}
	defer zero(a)
	b, err := deriveCredentialIntegrityKey(first)
	if err != nil {
		t.Fatal(err)
	}
	defer zero(b)
	c, err := deriveCredentialIntegrityKey(second)
	if err != nil {
		t.Fatal(err)
	}
	defer zero(c)
	if len(a) != 32 || !bytes.Equal(a, b) {
		t.Fatal("credential integrity derivation is not deterministic")
	}
	if bytes.Equal(a, first.Serialize()) {
		t.Fatal("provider scalar was used directly as the MAC key")
	}
	if bytes.Equal(a, c) {
		t.Fatal("distinct provider scalars derived the same MAC key")
	}
}

func TestOfflineKeyRejectsFixtureEncodings(t *testing.T) {
	fixtureRaw, err := hex.DecodeString(fixture.OfflinePubHex)
	if err != nil {
		t.Fatal(err)
	}
	fixturePub, err := btcec.ParsePubKey(fixtureRaw)
	if err != nil {
		t.Fatal(err)
	}
	for _, encoded := range []string{
		fixture.OfflinePubHex,
		strings.ToUpper(fixture.OfflinePubHex),
		hex.EncodeToString(negatePub(t, fixturePub).SerializeCompressed()),
		hex.EncodeToString(fixturePub.SerializeUncompressed()),
	} {
		if _, err := parseOfflinePub(encoded); err == nil {
			t.Fatalf("unsafe offline key accepted: %s", encoded)
		}
	}
}

func negatePub(t *testing.T, pub *btcec.PublicKey) *btcec.PublicKey {
	t.Helper()
	raw := append([]byte(nil), pub.SerializeCompressed()...)
	raw[0] ^= 1
	negated, err := btcec.ParsePubKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return negated
}

func TestRuntimeOwnsKeyAndLedgerAndDropsEnrollmentSecret(t *testing.T) {
	dir := t.TempDir()
	providerKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	offlineKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	providerPath := filepath.Join(dir, "provider-key")
	if err := os.WriteFile(providerPath, []byte(hex.EncodeToString(providerKey.Serialize())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const token = "one-time enrollment secret with enough entropy"
	tokenPath := filepath.Join(dir, "enrollment-token")
	if err := os.WriteFile(tokenPath, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Deployment: deployment.Config{
			ClientOrigin: "https://vault.example.com", RPID: "vault.example.com",
			Network: deployment.NetworkMutinynet, OperationalCSVBlocks: 288, SavingsCSVBlocks: 4032,
		},
		DatabasePath:    filepath.Join(dir, "vault.sqlite"),
		ProviderKeyFile: providerPath,
		OfflinePubHex:   hex.EncodeToString(offlineKey.PubKey().SerializeCompressed()),
		EsploraURL:      "https://mempool.mutinynet.arkade.sh/api",
	}
	dials := 0
	dial := func(_ context.Context, baseURL, network string) (provider.Broadcaster, error) {
		dials++
		if baseURL != cfg.EsploraURL || network != deployment.NetworkMutinynet {
			t.Fatalf("publisher identity = %q, %q", baseURL, network)
		}
		return stubPublisher{}, nil
	}
	emulatorDials := 0
	emulatorDial := func(_ context.Context, origin string, expected *btcec.PublicKey, versions []string, allowDeprecated bool) (provider.Signer, provider.PublicEmulatorIdentity, error) {
		emulatorDials++
		if origin != deployment.MutinynetArkadeEmulatorOrigin ||
			expected == nil || hex.EncodeToString(expected.SerializeCompressed()) != deployment.MutinynetArkadeEmulatorPubHex ||
			len(versions) != 1 || versions[0] != deployment.MutinynetArkadeEmulatorVersion {
			t.Fatalf("public emulator pin = %q %x %v", origin, expected.SerializeCompressed(), versions)
		}
		if allowDeprecated != (emulatorDials > 1) {
			t.Fatalf("public emulator deprecated-key allowance on dial %d = %v", emulatorDials, allowDeprecated)
		}
		return stubEmulatorSigner{}, provider.PublicEmulatorIdentity{
			Origin: origin, Version: versions[0], BasePub: expected,
		}, nil
	}

	if _, err := openWithDialers(context.Background(), cfg, dial, emulatorDial); err == nil || !strings.Contains(err.Error(), "enrollment token file") {
		t.Fatalf("fresh ledger without enrollment secret: %v", err)
	}
	if dials != 0 || emulatorDials != 0 {
		t.Fatal("external service contacted before fresh-ledger bootstrap validation")
	}

	cfg.EnrollmentTokenFile = tokenPath
	runtime, err := openWithDialers(context.Background(), cfg, dial, emulatorDial)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := runtime.service.Signer.(provider.LocalSigner); !ok {
		t.Fatalf("protected runtime signer = %T, want local policy-final signer", runtime.service.Signer)
	}
	if len(runtime.service.EnrollmentTokenHash) != 32 {
		t.Fatal("fresh runtime did not load the enrollment authorization hash")
	}
	if len(runtime.service.CredentialIntegrityKey) != 32 {
		t.Fatal("fresh runtime did not derive a credential integrity key")
	}
	passkey, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	hot, _ := btcec.NewPrivateKey()
	err = runtime.service.RegisterWithBootstrap(provider.RegisterRequest{
		CredentialID: hex.EncodeToString([]byte("mutinynet-credential")),
		WebAuthnP256: hex.EncodeToString(webauthn.CompressedP256(passkey)),
		DirectP256:   hex.EncodeToString(webauthn.CompressedP256(direct)),
		HotPub:       hex.EncodeToString(hot.PubKey().SerializeCompressed()),
	}, token)
	if err != nil {
		t.Fatal(err)
	}
	if len(runtime.service.EnrollmentTokenHash) != 0 {
		t.Fatal("successful enrollment retained the one-time authorization hash")
	}
	integrityAlias := runtime.service.CredentialIntegrityKey
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if len(runtime.service.CredentialIntegrityKey) != 0 || !bytes.Equal(integrityAlias, make([]byte, 32)) {
		t.Fatal("runtime close did not zero and release credential integrity key")
	}

	// A restart with a persisted enrollment neither requires nor reads the
	// one-time token. Pointing at an absent file makes that invariant explicit.
	cfg.EnrollmentTokenFile = filepath.Join(dir, "already-removed-token")
	restarted, err := openWithDialers(context.Background(), cfg, dial, emulatorDial)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if len(restarted.service.EnrollmentTokenHash) != 0 {
		t.Fatal("restart reloaded an enrollment token hash")
	}
	status, err := restarted.service.Status(context.Background())
	if err != nil || !status.Enrolled || status.Network != deployment.NetworkMutinynet {
		t.Fatalf("restart status = %+v, %v", status, err)
	}
}
