package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arkade-os/emulator/poc/2fa-vault/fixture"
	"github.com/arkade-os/emulator/poc/2fa-vault/internal/deployment"
	"github.com/arkade-os/emulator/poc/2fa-vault/internal/policy"
	"github.com/arkade-os/emulator/poc/2fa-vault/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func TestEnrollRoutesAreUnreachableWhenFlagOff(t *testing.T) {
	svc := &Service{Deployment: deployment.Config{ClientOrigin: "https://vault.example.com", RPID: "vault.example.com", Network: deployment.NetworkMutinynet}}
	h := AuthorizerHandler(svc)
	for _, path := range []string{"/v1/invite", "/v1/enroll/start", "/v1/enroll/finish"} {
		method := http.MethodPost
		body := "{}"
		if path == "/v1/invite" {
			method = http.MethodGet
			body = ""
		}
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Origin", "https://vault.example.com")
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: status %d, want 404", path, rec.Code)
		}
	}
}

func TestInviteStartFinishCASAndVaultScopedStatus(t *testing.T) {
	led, err := policy.OpenLedger(filepath.Join(t.TempDir(), "enroll.sqlite"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = led.Close() })
	master, _ := btcec.NewPrivateKey()
	arkade, _ := btcec.NewPrivateKey()
	owner, _ := btcec.NewPrivateKey()
	recovery, _ := btcec.NewPrivateKey()
	hot, _ := btcec.NewPrivateKey()
	pass, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	svc := &Service{
		Ledger: led, VaultCosignerPub: master.PubKey(), ArkadeCosignerPub: arkade.PubKey(),
		VaultSigner: LocalSigner{Priv: master}, ArkadeCosignerSigner: LocalSigner{Priv: arkade},
		Deployment: deployment.Config{
			ClientOrigin: fixture.Origin, RPID: fixture.RPID, Network: deployment.NetworkRegtest,
			OperationalCSVBlocks: 6, SavingsCSVBlocks: 144,
		},
		MultiTenantEnrollment: true,
	}
	raw := bytes.Repeat([]byte{0x3c}, 32)
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash, err := HashEnrollmentToken(token)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	if err := led.PutInvite(hash, now, now); err != nil {
		t.Fatal(err)
	}

	view, err := svc.InviteStatus(token)
	if err != nil || !view.CanEnroll || view.VaultID != nil {
		t.Fatalf("unused invite: %+v %v", view, err)
	}

	first, err := svc.StartEnrollment(token)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := svc.StartEnrollment(token)
	if err != nil {
		t.Fatal(err)
	}
	if first.VaultID != replay.VaultID || first.Handle != replay.Handle {
		t.Fatalf("start replay changed identity: %+v vs %+v", first, replay)
	}
	if first.UserID != hex.EncodeToString([]byte(first.VaultID)) {
		t.Fatal("user.id is not the assigned vault id bytes")
	}

	challenge, err := hex.DecodeString(replay.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	clientData := []byte(`{"type":"webauthn.create","challenge":"` + webauthn.EncodeChallenge(challenge) + `","origin":"` + fixture.Origin + `","crossOrigin":false}`)
	auth := make([]byte, 37)
	rpHash := sha256.Sum256([]byte(fixture.RPID))
	copy(auth[:32], rpHash[:])
	auth[32] = 0x05 // UP+UV

	req := EnrollFinishRequest{
		Handle:            replay.Handle,
		UserHandle:        replay.UserID,
		ClientDataJSON:    hex.EncodeToString(clientData),
		AuthenticatorData: hex.EncodeToString(auth),
		RegisterRequest: RegisterRequest{
			CredentialID:             hex.EncodeToString([]byte("cred-b")),
			WebAuthnP256:             hex.EncodeToString(webauthn.CompressedP256(pass)),
			PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(direct)),
			PhoneRoutineBIP340Pub:    hex.EncodeToString(hot.PubKey().SerializeCompressed()),
			ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(owner.PubKey())),
			RecoveryKeyXOnly:         hex.EncodeToString(schnorr.SerializePubKey(recovery.PubKey())),
		},
	}
	missing := req
	missing.ExternalOwnerWalletXOnly = ""
	if _, err := svc.FinishEnrollment(context.Background(), token, missing); err == nil {
		t.Fatal("finish accepted a tenant without owner/recovery pubs")
	}
	st, err := svc.FinishEnrollment(context.Background(), token, req)
	if err != nil {
		t.Fatal(err)
	}
	if st.VaultID != replay.VaultID || st.OperationalAddr == "" {
		t.Fatalf("finish status: %+v", st)
	}
	again, err := svc.FinishEnrollment(context.Background(), token, req)
	if err != nil || again.VaultID != st.VaultID {
		t.Fatalf("duplicate finish: %+v %v", again, err)
	}
	view, err = svc.InviteStatus(token)
	if err != nil || view.CanEnroll || view.VaultID == nil || *view.VaultID != replay.VaultID {
		t.Fatalf("consumed invite view: %+v %v", view, err)
	}

	other, _ := btcec.NewPrivateKey()
	forged := req
	forged.PhoneRoutineBIP340Pub = hex.EncodeToString(other.PubKey().SerializeCompressed())
	if _, err := svc.FinishEnrollment(context.Background(), token, forged); err == nil {
		t.Fatal("forged finish replaced the tenant")
	}
}

func TestFinishDoesNotInheritProcessOwnerPubs(t *testing.T) {
	led, err := policy.OpenLedger(filepath.Join(t.TempDir(), "inherit.sqlite"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = led.Close() })
	master, _ := btcec.NewPrivateKey()
	arkade, _ := btcec.NewPrivateKey()
	processOwner, _ := btcec.NewPrivateKey()
	processRec, _ := btcec.NewPrivateKey()
	hot, _ := btcec.NewPrivateKey()
	pass, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	svc := &Service{
		Ledger: led, ExternalOwnerWallet: processOwner.PubKey(), RecoveryKey: processRec.PubKey(),
		VaultCosignerPub: master.PubKey(), ArkadeCosignerPub: arkade.PubKey(),
		VaultSigner: LocalSigner{Priv: master}, ArkadeCosignerSigner: LocalSigner{Priv: arkade},
		Deployment: deployment.Config{
			ClientOrigin: fixture.Origin, RPID: fixture.RPID, Network: deployment.NetworkRegtest,
			OperationalCSVBlocks: 6, SavingsCSVBlocks: 144,
		},
		MultiTenantEnrollment: true,
	}
	raw := bytes.Repeat([]byte{0x4d}, 32)
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash, _ := HashEnrollmentToken(token)
	now := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	if err := led.PutInvite(hash, now, now); err != nil {
		t.Fatal(err)
	}
	start, err := svc.StartEnrollment(token)
	if err != nil {
		t.Fatal(err)
	}
	challenge, _ := hex.DecodeString(start.Challenge)
	clientData := []byte(`{"type":"webauthn.create","challenge":"` + webauthn.EncodeChallenge(challenge) + `","origin":"` + fixture.Origin + `","crossOrigin":false}`)
	auth := make([]byte, 37)
	rpHash := sha256.Sum256([]byte(fixture.RPID))
	copy(auth[:32], rpHash[:])
	auth[32] = 0x05
	_, err = svc.FinishEnrollment(context.Background(), token, EnrollFinishRequest{
		Handle: start.Handle, UserHandle: start.UserID,
		ClientDataJSON: hex.EncodeToString(clientData), AuthenticatorData: hex.EncodeToString(auth),
		RegisterRequest: RegisterRequest{
			CredentialID: hex.EncodeToString([]byte("cred-x")),
			WebAuthnP256: hex.EncodeToString(webauthn.CompressedP256(pass)),
			PhoneDirectP256: hex.EncodeToString(webauthn.CompressedP256(direct)),
			PhoneRoutineBIP340Pub: hex.EncodeToString(hot.PubKey().SerializeCompressed()),
		},
	})
	if err == nil {
		t.Fatal("finish inherited process-level owner/recovery pubs")
	}
}

func TestCredentialCannotOperateAnotherVault(t *testing.T) {
	svc := &Service{}
	svc.publishEnrollmentAt("vault-a", []byte("cred-a"), nil, nil, nil)
	svc.publishEnrollmentAt("vault-b", []byte("cred-b"), nil, nil, nil)
	if err := svc.rejectCrossVaultCredential("vault-b", []byte("cred-a")); err == nil {
		t.Fatal("credential A operated vault B")
	}
	if err := svc.rejectCrossVaultCredential("vault-a", []byte("cred-a")); err != nil {
		t.Fatal(err)
	}
}
