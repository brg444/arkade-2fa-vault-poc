package provider

import (
	"bytes"
	"encoding/hex"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/arkade-os/emulator/poc/2fa-vault/internal/policy"
	"github.com/arkade-os/emulator/poc/2fa-vault/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
)

func TestRegisterExactRetryAcceptedAndMismatchesStayLocked(t *testing.T) {
	svc, req := newRegisterableService(t)
	if err := svc.Register(req); err != nil {
		t.Fatalf("first register: %v", err)
	}
	wantAddr := svc.Operational.Address

	retry := req
	retry.CredentialID = strings.ToUpper(req.CredentialID)
	retry.WebAuthnP256 = strings.ToUpper(req.WebAuthnP256)
	retry.DirectP256 = strings.ToUpper(req.DirectP256)
	retry.HotPub = strings.ToUpper(req.HotPub)
	if err := svc.Register(retry); err != nil {
		t.Fatalf("exact retry: %v", err)
	}
	if svc.Operational.Address != wantAddr {
		t.Fatal("exact retry changed the enrolled operational address")
	}

	if err := svc.Register(RegisterRequest{
		CredentialID: "zz",
		WebAuthnP256: req.WebAuthnP256,
		DirectP256:   req.DirectP256,
		HotPub:       req.HotPub,
	}); err == nil || !strings.Contains(err.Error(), "hex") {
		t.Fatalf("malformed retry before compare: %v", err)
	}

	mismatches := []struct {
		name string
		mut  func(*RegisterRequest)
	}{
		{"credential id", func(r *RegisterRequest) { r.CredentialID = hex.EncodeToString([]byte{0x99}) }},
		{"webauthn p256", func(r *RegisterRequest) { r.WebAuthnP256 = otherP256(t) }},
		{"direct p256", func(r *RegisterRequest) { r.DirectP256 = otherP256(t) }},
		{"hot pub", func(r *RegisterRequest) { r.HotPub = otherHot(t) }},
	}
	for _, test := range mismatches {
		t.Run(test.name, func(t *testing.T) {
			bad := req
			test.mut(&bad)
			err := svc.Register(bad)
			if err == nil || !strings.Contains(err.Error(), "enrollment locked") {
				t.Fatalf("mismatch %s: %v", test.name, err)
			}
		})
	}
}

func newRegisterableService(t *testing.T) (*Service, RegisterRequest) {
	t.Helper()
	hot, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	offline, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	prov, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	passkey, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	direct, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	led, err := policy.OpenLedger(filepath.Join(t.TempDir(), "register.sqlite"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = led.Close() })
	svc := &Service{
		Ledger:      led,
		Offline:     offline.PubKey(),
		ProviderPub: prov.PubKey(),
		Signer:      LocalSigner{Priv: prov},
	}
	req := RegisterRequest{
		CredentialID: hex.EncodeToString([]byte("enroll-credential")),
		WebAuthnP256: hex.EncodeToString(webauthn.CompressedP256(passkey)),
		DirectP256:   hex.EncodeToString(webauthn.CompressedP256(direct)),
		HotPub:       hex.EncodeToString(hot.PubKey().SerializeCompressed()),
	}
	return svc, req
}

func otherP256(t *testing.T) string {
	t.Helper()
	key, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(webauthn.CompressedP256(key))
}

func TestRegisterSameTupleDifferentRuntimeRaceDoesNotPublishLoser(t *testing.T) {
	t.Run("different provider", func(t *testing.T) {
		runSameTupleRuntimeRace(t, true, false)
	})
	t.Run("different offline", func(t *testing.T) {
		runSameTupleRuntimeRace(t, false, true)
	})
}

func runSameTupleRuntimeRace(t *testing.T, differentProvider, differentOffline bool) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "same-tuple-race.sqlite")
	ledgers := make([]*policy.Ledger, 2)
	for i := range ledgers {
		led, err := policy.OpenLedger(dbPath, nil)
		if err != nil {
			t.Fatalf("open ledger %d: %v", i, err)
		}
		ledgers[i] = led
		t.Cleanup(func() { _ = led.Close() })
	}

	hot, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	passkey, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	direct, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	offlineA, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	offlineB := offlineA
	if differentOffline {
		offlineB, err = btcec.NewPrivateKey()
		if err != nil {
			t.Fatal(err)
		}
	}
	provA, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	provB := provA
	if differentProvider {
		provB, err = btcec.NewPrivateKey()
		if err != nil {
			t.Fatal(err)
		}
	}

	req := RegisterRequest{
		CredentialID: hex.EncodeToString([]byte("shared-credential")),
		WebAuthnP256: hex.EncodeToString(webauthn.CompressedP256(passkey)),
		DirectP256:   hex.EncodeToString(webauthn.CompressedP256(direct)),
		HotPub:       hex.EncodeToString(hot.PubKey().SerializeCompressed()),
	}
	type handle struct {
		svc *Service
		err error
	}
	handles := []handle{
		{svc: &Service{
			Ledger:      ledgers[0],
			Offline:     offlineA.PubKey(),
			ProviderPub: provA.PubKey(),
			Signer:      LocalSigner{Priv: provA},
		}},
		{svc: &Service{
			Ledger:      ledgers[1],
			Offline:     offlineB.PubKey(),
			ProviderPub: provB.PubKey(),
			Signer:      LocalSigner{Priv: provB},
		}},
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range handles {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			handles[i].err = handles[i].svc.Register(req)
		}(i)
	}
	close(start)
	wg.Wait()

	var winner, loser int
	switch {
	case handles[0].err == nil && handles[1].err != nil:
		winner, loser = 0, 1
	case handles[1].err == nil && handles[0].err != nil:
		winner, loser = 1, 0
	default:
		t.Fatalf("want exactly one success: err0=%v err1=%v", handles[0].err, handles[1].err)
	}
	lost := handles[loser].svc
	if lost.Hot != nil || lost.Operational != nil || lost.Savings != nil {
		t.Fatal("losing handle published vault state")
	}
	if snap := lost.enrolled(); snap.Hot != nil || snap.Operational != nil || snap.Savings != nil {
		t.Fatal("losing handle published an enrollment snapshot")
	}

	persisted, err := ledgers[0].GetCredential()
	if err != nil || persisted == nil {
		t.Fatalf("persisted enrollment: %v", err)
	}
	wantProv := handles[winner].svc.ProviderPub.SerializeCompressed()
	wantOff := handles[winner].svc.Offline.SerializeCompressed()
	if !bytes.Equal(persisted.ProviderBase, wantProv) || !bytes.Equal(persisted.Offline, wantOff) {
		t.Fatal("persisted descriptor is not the winner's runtime keys")
	}
	if handles[winner].svc.Operational == nil ||
		handles[winner].svc.Operational.Address != persisted.OperationalAddress {
		t.Fatal("winner did not publish the persisted operational vault")
	}
	if bytes.Equal(lost.ProviderPub.SerializeCompressed(), persisted.ProviderBase) &&
		bytes.Equal(lost.Offline.SerializeCompressed(), persisted.Offline) {
		t.Fatal("test setup failed: loser runtime matches persisted descriptor")
	}
}

func otherHot(t *testing.T) string {
	t.Helper()
	key, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(key.PubKey().SerializeCompressed())
}
