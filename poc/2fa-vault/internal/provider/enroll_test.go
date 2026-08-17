package provider

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
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
	if first.Challenge != replay.Challenge {
		t.Fatal("unexpired start replay rotated the challenge")
	}

	req := attestedFinish(t, replay, pass, []byte("cred-b"), RegisterRequest{
		PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneRoutineBIP340Pub:    hex.EncodeToString(hot.PubKey().SerializeCompressed()),
		ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(owner.PubKey())),
		RecoveryKeyXOnly:         hex.EncodeToString(schnorr.SerializePubKey(recovery.PubKey())),
	})
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
	_, err = svc.FinishEnrollment(context.Background(), token, attestedFinish(t, start, pass, []byte("cred-x"), RegisterRequest{
		PhoneDirectP256:       hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneRoutineBIP340Pub: hex.EncodeToString(hot.PubKey().SerializeCompressed()),
	}))
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

func attestedFinish(t *testing.T, start *EnrollStartResponse, pass *ecdsa.PrivateKey, credID []byte, extra RegisterRequest) EnrollFinishRequest {
	t.Helper()
	challenge, err := hex.DecodeString(start.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	compressed := webauthn.CompressedP256(pass)
	auth, err := webauthn.AttestedAuthenticatorData(fixture.RPID, credID, compressed)
	if err != nil {
		t.Fatal(err)
	}
	obj := webauthn.EncodeNoneAttestationObject(auth)
	extra.CredentialID = hex.EncodeToString(credID)
	extra.WebAuthnP256 = hex.EncodeToString(compressed)
	return EnrollFinishRequest{
		Handle:            start.Handle,
		UserHandle:        start.UserID,
		ClientDataJSON:    hex.EncodeToString([]byte(`{"type":"webauthn.create","challenge":"` + webauthn.EncodeChallenge(challenge) + `","origin":"` + fixture.Origin + `","crossOrigin":false}`)),
		AuthenticatorData: hex.EncodeToString(auth),
		AttestationObject: hex.EncodeToString(obj),
		RegisterRequest:   extra,
	}
}

func TestFinishRejectsUnattestedOrMismatchedCreate(t *testing.T) {
	svc, token, start := enrollReady(t)
	pass, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	hot, _ := btcec.NewPrivateKey()
	owner, _ := btcec.NewPrivateKey()
	recovery, _ := btcec.NewPrivateKey()
	req := attestedFinish(t, start, pass, []byte("cred-at"), RegisterRequest{
		PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneRoutineBIP340Pub:    hex.EncodeToString(hot.PubKey().SerializeCompressed()),
		ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(owner.PubKey())),
		RecoveryKeyXOnly:         hex.EncodeToString(schnorr.SerializePubKey(recovery.PubKey())),
	})
	noAT := req
	auth := make([]byte, 37)
	copy(auth[:32], mustDecode(t, req.AuthenticatorData)[:32])
	auth[32] = 0x05
	noAT.AuthenticatorData = hex.EncodeToString(auth)
	noAT.AttestationObject = ""
	if _, err := svc.FinishEnrollment(context.Background(), token, noAT); err == nil {
		t.Fatal("finish accepted create without AT")
	}
	mismatch := req
	other, _ := webauthn.NewP256()
	mismatch.WebAuthnP256 = hex.EncodeToString(webauthn.CompressedP256(other))
	if _, err := svc.FinishEnrollment(context.Background(), token, mismatch); err == nil {
		t.Fatal("finish accepted a posted P-256 that was not attested")
	}
}

func TestStaleStartChallengeCannotFinishAfterExpiryRotation(t *testing.T) {
	svc, token, start := enrollReady(t)
	stale := start.Challenge
	now := time.Now().UTC()
	svc.EnrollmentNow = func() time.Time { return now.Add(pendingEnrollmentTTL + time.Minute) }
	rotated, err := svc.StartEnrollment(token)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Challenge == stale {
		t.Fatal("expired start did not rotate the challenge")
	}
	start.Challenge = stale
	pass, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	hot, _ := btcec.NewPrivateKey()
	owner, _ := btcec.NewPrivateKey()
	recovery, _ := btcec.NewPrivateKey()
	staleReq := attestedFinish(t, start, pass, []byte("stale"), RegisterRequest{
		PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneRoutineBIP340Pub:    hex.EncodeToString(hot.PubKey().SerializeCompressed()),
		ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(owner.PubKey())),
		RecoveryKeyXOnly:         hex.EncodeToString(schnorr.SerializePubKey(recovery.PubKey())),
	})
	if _, err := svc.FinishEnrollment(context.Background(), token, staleReq); err == nil {
		t.Fatal("stale challenge finished after rotation")
	}
	fresh, _ := webauthn.NewP256()
	if _, err := svc.FinishEnrollment(context.Background(), token, attestedFinish(t, rotated, fresh, []byte("fresh"), staleReq.RegisterRequest)); err != nil {
		t.Fatal(err)
	}
}

func TestSecondTenantStatusDoesNotInspectFirstVaultEnvelope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "envelope-iso.sqlite")
	led, err := policy.OpenLedger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = led.Close() })
	svc := enrollService(t, led)
	if err := registerFirstVault(t, svc); err != nil {
		t.Fatal(err)
	}
	key, err := svc.credentialIntegrityKey()
	if err != nil {
		t.Fatal(err)
	}
	cred, err := led.GetCredential()
	if err != nil || cred == nil {
		t.Fatal(err)
	}
	env := policy.CredentialEnvelope{
		Version: policy.CredentialEnvelopeVersion, Binding: `{"v":1}`,
		Nonce: bytes.Repeat([]byte{0x11}, 12), Ciphertext: bytes.Repeat([]byte{0x22}, 48),
		DirectSig: bytes.Repeat([]byte{0x33}, 64), PhoneSig: bytes.Repeat([]byte{0x44}, 64),
	}
	if err := policy.SealCredentialEnvelope(&env, cred.ID, key); err != nil {
		t.Fatal(err)
	}
	if err := led.SetIntegrityKey(key); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateLegacySingleton(key); err != nil {
		t.Fatal(err)
	}
	if err := led.StoreCredentialEnvelopeIfAbsent(env); err != nil {
		t.Fatal(err)
	}
	first, err := svc.statusFor(context.Background(), fixture.VaultID)
	if err != nil || !first.PasskeyLoginAvailable {
		t.Fatalf("first vault envelope: %+v %v", first, err)
	}

	raw := bytes.Repeat([]byte{0x61}, 32)
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
	pass, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	hot, _ := btcec.NewPrivateKey()
	owner, _ := btcec.NewPrivateKey()
	recovery, _ := btcec.NewPrivateKey()
	second, err := svc.FinishEnrollment(context.Background(), token, attestedFinish(t, start, pass, []byte("cred-b"), RegisterRequest{
		PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneRoutineBIP340Pub:    hex.EncodeToString(hot.PubKey().SerializeCompressed()),
		ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(owner.PubKey())),
		RecoveryKeyXOnly:         hex.EncodeToString(schnorr.SerializePubKey(recovery.PubKey())),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if second.PasskeyLoginAvailable {
		t.Fatal("second tenant inherited the first vault envelope")
	}
	if first2, err := svc.statusFor(context.Background(), fixture.VaultID); err != nil || !first2.PasskeyLoginAvailable {
		t.Fatalf("first vault status after second enroll: %+v %v", first2, err)
	}

	reopened, err := policy.OpenLedger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	restarted := enrollService(t, reopened)
	restarted.VaultCosignerPub = svc.VaultCosignerPub
	restarted.ArkadeCosignerPub = svc.ArkadeCosignerPub
	restarted.VaultSigner = svc.VaultSigner
	restarted.ArkadeCosignerSigner = svc.ArkadeCosignerSigner
	restarted.ExternalOwnerWallet = svc.ExternalOwnerWallet
	restarted.RecoveryKey = svc.RecoveryKey
	if err := restarted.LoadVaults(); err != nil {
		t.Fatal(err)
	}
	gotFirst, err := restarted.statusFor(context.Background(), fixture.VaultID)
	if err != nil || !gotFirst.PasskeyLoginAvailable {
		t.Fatalf("restart first: %+v %v", gotFirst, err)
	}
	gotSecond, err := restarted.statusFor(context.Background(), second.VaultID)
	if err != nil || gotSecond.PasskeyLoginAvailable {
		t.Fatalf("restart second: %+v %v", gotSecond, err)
	}
}

func TestConcurrentFinishAndStatusDoNotRaceSharedKeyFields(t *testing.T) {
	svc, token, start := enrollReady(t)
	pass, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	hot, _ := btcec.NewPrivateKey()
	owner, _ := btcec.NewPrivateKey()
	recovery, _ := btcec.NewPrivateKey()
	req := attestedFinish(t, start, pass, []byte("race"), RegisterRequest{
		PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneRoutineBIP340Pub:    hex.EncodeToString(hot.PubKey().SerializeCompressed()),
		ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(owner.PubKey())),
		RecoveryKeyXOnly:         hex.EncodeToString(schnorr.SerializePubKey(recovery.PubKey())),
	})
	if _, err := svc.FinishEnrollment(context.Background(), token, req); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errCh := make(chan error, 32)
	for i := 0; i < 8; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			if _, err := svc.FinishEnrollment(context.Background(), token, req); err != nil {
				errCh <- err
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := svc.Status(context.Background()); err != nil {
				errCh <- err
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := svc.statusFor(context.Background(), start.VaultID); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}

func enrollReady(t *testing.T) (*Service, string, *EnrollStartResponse) {
	t.Helper()
	led, err := policy.OpenLedger(filepath.Join(t.TempDir(), "ready.sqlite"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = led.Close() })
	svc := enrollService(t, led)
	svc.MultiTenantEnrollment = true
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
	start, err := svc.StartEnrollment(token)
	if err != nil {
		t.Fatal(err)
	}
	return svc, token, start
}

func enrollService(t *testing.T, led *policy.Ledger) *Service {
	t.Helper()
	master, _ := btcec.NewPrivateKey()
	arkade, _ := btcec.NewPrivateKey()
	return &Service{
		Ledger: led, VaultCosignerPub: master.PubKey(), ArkadeCosignerPub: arkade.PubKey(),
		VaultSigner: LocalSigner{Priv: master}, ArkadeCosignerSigner: LocalSigner{Priv: arkade},
		Deployment: deployment.Config{
			ClientOrigin: fixture.Origin, RPID: fixture.RPID, Network: deployment.NetworkRegtest,
			OperationalCSVBlocks: 6, SavingsCSVBlocks: 144,
		},
		MultiTenantEnrollment: true,
	}
}

func registerFirstVault(t *testing.T, svc *Service) error {
	t.Helper()
	owner, _ := btcec.NewPrivateKey()
	recovery, _ := btcec.NewPrivateKey()
	svc.ExternalOwnerWallet = owner.PubKey()
	svc.RecoveryKey = recovery.PubKey()
	hot, _ := btcec.NewPrivateKey()
	pass, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	return svc.Register(RegisterRequest{
		CredentialID:          hex.EncodeToString([]byte("cred-a")),
		WebAuthnP256:          hex.EncodeToString(webauthn.CompressedP256(pass)),
		PhoneDirectP256:       hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneRoutineBIP340Pub: hex.EncodeToString(hot.PubKey().SerializeCompressed()),
	})
}

func mustDecode(t *testing.T, h string) []byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
