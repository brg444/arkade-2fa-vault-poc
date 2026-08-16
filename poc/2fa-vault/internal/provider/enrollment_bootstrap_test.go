package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arkade-os/emulator/poc/2fa-vault/internal/policy"
	"github.com/arkade-os/emulator/poc/2fa-vault/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
)

func TestFirstEnrollmentRequiresBootstrapAndTokenCannotReplaceEnrollment(t *testing.T) {
	ledger, err := policy.OpenLedger(filepath.Join(t.TempDir(), "bootstrap.sqlite"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	offline, _ := btcec.NewPrivateKey()
	providerKey, _ := btcec.NewPrivateKey()
	arkadeKey, _ := btcec.NewPrivateKey()
	hot, _ := btcec.NewPrivateKey()
	passkey, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	const token = "correct horse battery staple enrollment token"
	digest := sha256.Sum256([]byte(token))
	svc := &Service{
		Ledger: ledger, Offline: offline.PubKey(), ProviderPub: providerKey.PubKey(), ArkadePub: arkadeKey.PubKey(),
		Signer: LocalSigner{Priv: providerKey}, ArkadeSigner: LocalSigner{Priv: arkadeKey}, EnrollmentTokenHash: digest[:],
	}
	req := RegisterRequest{
		CredentialID: hex.EncodeToString([]byte("credential-a")),
		WebAuthnP256: hex.EncodeToString(webauthn.CompressedP256(passkey)),
		DirectP256:   hex.EncodeToString(webauthn.CompressedP256(direct)),
		HotPub:       hex.EncodeToString(hot.PubKey().SerializeCompressed()),
	}
	for _, attempt := range []string{"", "wrong and must never be reflected"} {
		err := svc.RegisterWithBootstrap(req, attempt)
		if err == nil || !strings.Contains(err.Error(), "bootstrap authorization failed") {
			t.Fatalf("bootstrap %q: %v", attempt, err)
		}
		if strings.Contains(err.Error(), attempt) && attempt != "" {
			t.Fatal("bootstrap error reflected token material")
		}
		cred, getErr := ledger.GetCredential()
		if getErr != nil || cred != nil {
			t.Fatalf("failed bootstrap mutated enrollment: cred=%v err=%v", cred, getErr)
		}
	}
	if err := svc.RegisterWithBootstrap(req, token); err != nil {
		t.Fatalf("correct bootstrap: %v", err)
	}
	if len(svc.EnrollmentTokenHash) != 0 {
		t.Fatal("successful enrollment retained the bootstrap token hash")
	}

	// Crash-recovery idempotency no longer depends on the bootstrap token.
	if err := svc.RegisterWithBootstrap(req, ""); err != nil {
		t.Fatalf("exact post-enrollment retry: %v", err)
	}

	otherHot, _ := btcec.NewPrivateKey()
	forged := req
	forged.HotPub = hex.EncodeToString(otherHot.PubKey().SerializeCompressed())
	if err := svc.RegisterWithBootstrap(forged, token); err == nil || !strings.Contains(err.Error(), "enrollment locked") {
		t.Fatalf("consumed bootstrap token replaced enrollment: %v", err)
	}
}
