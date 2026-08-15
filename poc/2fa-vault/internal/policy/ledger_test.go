package policy

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arkade-os/emulator/poc/2fa-vault/fixture"
	"github.com/btcsuite/btcd/btcec/v2"
)

type manualClock struct {
	mu  sync.RWMutex
	now time.Time
}

func newManualClock(now time.Time) *manualClock {
	return &manualClock{now: now}
}

func (c *manualClock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.now
}

func (c *manualClock) Set(now time.Time) {
	c.mu.Lock()
	c.now = now
	c.mu.Unlock()
}

func openTestLedger(t *testing.T, clock Clock) *Ledger {
	t.Helper()
	led, err := OpenLedger(filepath.Join(t.TempDir(), "ledger.sqlite"), clock)
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	t.Cleanup(func() {
		if err := led.Close(); err != nil {
			t.Errorf("close ledger: %v", err)
		}
	})
	return led
}

func digest(tag byte) []byte {
	return bytes.Repeat([]byte{tag}, 32)
}

func validCredential(tag byte) Credential {
	curve := elliptic.P256()
	p256 := elliptic.MarshalCompressed(curve, curve.Params().Gx, curve.Params().Gy)
	dx, dy := curve.ScalarBaseMult([]byte{0x03})
	directP256 := elliptic.MarshalCompressed(curve, dx, dy)
	hotPriv, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{tag}, 32))
	offPriv, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{tag + 3}, 32))
	provPriv, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{tag + 5}, 32))
	tweakPriv, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{tag + 7}, 32))
	opCSV := fixture.OperationalCSV()
	svCSV := fixture.SavingsCSV()
	return Credential{
		ID:                  []byte{tag, tag + 1, tag + 2},
		WebAuthnP256:        p256,
		DirectP256:          directP256,
		Hot:                 hotPriv.PubKey().SerializeCompressed(),
		RPID:                "localhost",
		Origin:              "http://localhost:7072",
		Offline:             offPriv.PubKey().SerializeCompressed(),
		ProviderBase:        provPriv.PubKey().SerializeCompressed(),
		TweakedProvider:     tweakPriv.PubKey().SerializeCompressed(),
		TemplateVersion:     fixture.TemplateVersion,
		PolicyVersion:       fixture.PolicyVersion,
		Network:             fixture.Network,
		VaultID:             fixture.VaultID,
		OperationalCSVType:  int64(opCSV.Type),
		OperationalCSVValue: opCSV.Value,
		SavingsCSVType:      int64(svCSV.Type),
		SavingsCSVValue:     svCSV.Value,
		OperationalAddress:  fmt.Sprintf("bcrt1qop-%d", tag),
		OperationalScript:   []byte{0x51, 0x20, tag},
		SavingsAddress:      fmt.Sprintf("bcrt1qsv-%d", tag),
		SavingsScript:       []byte{0x51, 0x20, tag + 1},
	}
}

func TestEnrollmentIsOneShotRetrievableAndDurable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrollment.sqlite")
	clock := newManualClock(time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC))
	led, err := OpenLedger(path, clock.Now)
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}

	got, err := led.GetCredential()
	if err != nil {
		t.Fatalf("get empty credential: %v", err)
	}
	if got != nil {
		t.Fatalf("new ledger returned credential: %+v", got)
	}

	original := validCredential(0x21)
	if err := led.Enroll(original); err != nil {
		t.Fatalf("first enrollment: %v", err)
	}
	assertCredentialEqual(t, led, original)

	replacement := validCredential(0x42)
	if err := led.Enroll(replacement); err == nil {
		t.Fatal("second enrollment replaced the locked credential")
	}
	assertCredentialEqual(t, led, original)

	if err := led.Close(); err != nil {
		t.Fatalf("close ledger: %v", err)
	}
	reopened, err := OpenLedger(path, clock.Now)
	if err != nil {
		t.Fatalf("reopen ledger: %v", err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("close reopened ledger: %v", err)
		}
	})
	assertCredentialEqual(t, reopened, original)
	if err := reopened.Enroll(replacement); err == nil {
		t.Fatal("process restart unlocked enrollment")
	}
}

func assertCredentialEqual(t *testing.T, led *Ledger, want Credential) {
	t.Helper()
	got, err := led.GetCredential()
	if err != nil {
		t.Fatalf("get credential: %v", err)
	}
	if got == nil {
		t.Fatal("credential missing")
	}
	if !bytes.Equal(got.ID, want.ID) || !bytes.Equal(got.WebAuthnP256, want.WebAuthnP256) || !bytes.Equal(got.DirectP256, want.DirectP256) || !bytes.Equal(got.Hot, want.Hot) ||
		got.RPID != want.RPID || got.Origin != want.Origin ||
		!bytes.Equal(got.Offline, want.Offline) || !bytes.Equal(got.ProviderBase, want.ProviderBase) ||
		!bytes.Equal(got.TweakedProvider, want.TweakedProvider) ||
		got.TemplateVersion != want.TemplateVersion || got.PolicyVersion != want.PolicyVersion ||
		got.Network != want.Network || got.VaultID != want.VaultID ||
		got.OperationalCSVType != want.OperationalCSVType || got.OperationalCSVValue != want.OperationalCSVValue ||
		got.SavingsCSVType != want.SavingsCSVType || got.SavingsCSVValue != want.SavingsCSVValue ||
		got.OperationalAddress != want.OperationalAddress || got.SavingsAddress != want.SavingsAddress ||
		!bytes.Equal(got.OperationalScript, want.OperationalScript) || !bytes.Equal(got.SavingsScript, want.SavingsScript) {
		t.Fatalf("credential mismatch\n got: %+v\nwant: %+v", got, want)
	}
}

func TestConcurrentFirstEnrollmentHasOneAtomicDurableWinner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrollment-race.sqlite")
	clock := newManualClock(time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC))
	ledgers := make([]*Ledger, 2)
	for i := range ledgers {
		led, err := OpenLedger(path, clock.Now)
		if err != nil {
			t.Fatalf("open ledger handle %d: %v", i, err)
		}
		ledgers[i] = led
		t.Cleanup(func() { _ = led.Close() })
	}

	candidates := []Credential{validCredential(0x23), validCredential(0x45)}
	curve := elliptic.P256()
	x, y := curve.ScalarBaseMult([]byte{0x02})
	candidates[1].WebAuthnP256 = elliptic.MarshalCompressed(curve, x, y)
	candidates[0].RPID = "first.local"
	candidates[0].Origin = "https://first.local"
	candidates[1].RPID = "second.local"
	candidates[1].Origin = "https://second.local"

	type result struct {
		candidate int
		err       error
	}
	start := make(chan struct{})
	results := make(chan result, len(candidates))
	var wg sync.WaitGroup
	for i := range candidates {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results <- result{candidate: i, err: ledgers[i].Enroll(candidates[i])}
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)

	winner := -1
	failed := 0
	for result := range results {
		if result.err == nil {
			if winner != -1 {
				t.Fatalf("multiple concurrent enrollments succeeded: candidates %d and %d", winner, result.candidate)
			}
			winner = result.candidate
			continue
		}
		failed++
	}
	if winner == -1 || failed != 1 {
		t.Fatalf("enrollment race winner=%d failures=%d; want one winner and one failure", winner, failed)
	}

	for i, led := range ledgers {
		assertCredentialEqual(t, led, candidates[winner])
		if err := led.Close(); err != nil {
			t.Fatalf("close ledger handle %d: %v", i, err)
		}
	}
	reopened, err := OpenLedger(path, clock.Now)
	if err != nil {
		t.Fatalf("reopen ledger after enrollment race: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	assertCredentialEqual(t, reopened, candidates[winner])
}

func TestPeriodStartAndAllowanceRolloverAtUTCMidnight(t *testing.T) {
	utcPlusEight := time.FixedZone("UTC+8", 8*60*60)
	clock := newManualClock(time.Date(2026, 8, 16, 7, 59, 59, 0, utcPlusEight))
	led := openTestLedger(t, clock.Now)
	ctx := context.Background()

	if got, want := led.PeriodStart(), "2026-08-15"; got != want {
		t.Fatalf("period before rollover = %q, want %q", got, want)
	}
	if _, _, err := led.Issue(ctx, "vault-a", digest(0x01), 90, 3, 100,
		func(context.Context) (string, error) { return "signed-day-one", nil }); err != nil {
		t.Fatalf("day-one issue: %v", err)
	}

	clock.Set(time.Date(2026, 8, 16, 8, 0, 0, 0, utcPlusEight))
	if got, want := led.PeriodStart(), "2026-08-16"; got != want {
		t.Fatalf("period after rollover = %q, want %q", got, want)
	}
	if _, _, err := led.Issue(ctx, "vault-a", digest(0x02), 90, 3, 100,
		func(context.Context) (string, error) { return "signed-day-two", nil }); err != nil {
		t.Fatalf("new UTC period did not reset allowance: %v", err)
	}

	for period, want := range map[string]int64{"2026-08-15": 93, "2026-08-16": 93} {
		got, err := led.SpentInPeriod(ctx, "vault-a", period)
		if err != nil {
			t.Fatalf("spent in %s: %v", period, err)
		}
		if got != want {
			t.Fatalf("spent in %s = %d, want %d", period, got, want)
		}
	}
}

func TestSequentialIssuesRespectExactAllowance(t *testing.T) {
	clock := newManualClock(time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC))
	led := openTestLedger(t, clock.Now)
	ctx := context.Background()
	var calls atomic.Int32
	sign := func(label string) AuthorizeFn {
		return func(context.Context) (string, error) {
			calls.Add(1)
			return label, nil
		}
	}

	if _, _, err := led.Issue(ctx, "vault-a", digest(0x10), 40, 2, 100, sign("signed-40")); err != nil {
		t.Fatalf("first issue: %v", err)
	}
	if _, _, err := led.Issue(ctx, "vault-a", digest(0x11), 51, 7, 100, sign("signed-58")); err != nil {
		t.Fatalf("issue at exact allowance: %v", err)
	}
	if _, _, err := led.Issue(ctx, "vault-a", digest(0x12), 1, 0, 100, sign("must-not-sign")); err == nil {
		t.Fatal("issue above allowance succeeded")
	} else if !strings.Contains(err.Error(), "allowance") {
		t.Fatalf("issue above allowance returned non-policy error: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("signer calls = %d, want 2", got)
	}
	spent, err := led.SpentInPeriod(ctx, "vault-a", led.PeriodStart())
	if err != nil {
		t.Fatalf("spent: %v", err)
	}
	if spent != 100 {
		t.Fatalf("spent = %d, want 100", spent)
	}
}

func TestConcurrentIssuesCannotCollectivelyExceedAllowance(t *testing.T) {
	clock := newManualClock(time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC))
	led := openTestLedger(t, clock.Now)
	const requests = 8

	start := make(chan struct{})
	results := make(chan error, requests)
	var wg sync.WaitGroup
	var signerCalls atomic.Int32
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, _, err := led.Issue(
				context.Background(),
				"vault-a",
				digest(byte(0x20+i)),
				40,
				1,
				100,
				func(context.Context) (string, error) {
					signerCalls.Add(1)
					return fmt.Sprintf("signed-%d", i), nil
				},
			)
			results <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)

	var succeeded, rejected int
	for err := range results {
		if err == nil {
			succeeded++
			continue
		}
		if !strings.Contains(err.Error(), "allowance") {
			t.Fatalf("concurrent request failed for a non-policy reason: %v", err)
		}
		rejected++
	}
	if succeeded != 2 || rejected != 6 {
		t.Fatalf("concurrent results: %d succeeded, %d rejected; want 2 and 6", succeeded, rejected)
	}
	if got := signerCalls.Load(); got != 2 {
		t.Fatalf("signer calls = %d, want exactly 2", got)
	}
	spent, err := led.SpentInPeriod(context.Background(), "vault-a", led.PeriodStart())
	if err != nil {
		t.Fatalf("spent: %v", err)
	}
	if spent != 82 {
		t.Fatalf("spent = %d, want 82", spent)
	}
}

func TestConcurrentLedgerHandlesCannotInterleaveBudgetCheckAndReservation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.sqlite")
	clock := newManualClock(time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC))
	ledgers := make([]*Ledger, 2)
	for i := range ledgers {
		led, err := OpenLedger(path, clock.Now)
		if err != nil {
			t.Fatalf("open ledger handle %d: %v", i, err)
		}
		ledgers[i] = led
		t.Cleanup(func() {
			if err := led.Close(); err != nil {
				t.Errorf("close ledger handle %d: %v", i, err)
			}
		})
	}

	const requests = 8
	start := make(chan struct{})
	results := make(chan error, requests)
	var wg sync.WaitGroup
	var signerCalls atomic.Int32
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, _, err := ledgers[i%len(ledgers)].Issue(
				context.Background(),
				"vault-a",
				digest(byte(0x30+i)),
				40,
				1,
				100,
				func(context.Context) (string, error) {
					signerCalls.Add(1)
					return fmt.Sprintf("signed-%d", i), nil
				},
			)
			results <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)

	var succeeded, rejected int
	for err := range results {
		if err == nil {
			succeeded++
			continue
		}
		if !strings.Contains(err.Error(), "allowance") {
			t.Fatalf("shared-ledger request failed for a non-policy reason: %v", err)
		}
		rejected++
	}
	if succeeded != 2 || rejected != 6 {
		t.Fatalf("shared-ledger results: %d succeeded, %d rejected; want 2 and 6", succeeded, rejected)
	}
	if got := signerCalls.Load(); got != 2 {
		t.Fatalf("signer calls = %d, want exactly 2", got)
	}
	spent, err := ledgers[0].SpentInPeriod(context.Background(), "vault-a", ledgers[0].PeriodStart())
	if err != nil {
		t.Fatalf("spent: %v", err)
	}
	if spent != 82 {
		t.Fatalf("spent = %d, want 82", spent)
	}
}

func TestPostSubmitSignerFailureRemainsReserved(t *testing.T) {
	tests := []struct {
		name    string
		signErr error
	}{
		{name: "signer failure", signErr: errors.New("signer unavailable")},
		{name: "signer timeout", signErr: context.DeadlineExceeded},
	}
	for i, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := newManualClock(time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC))
			led := openTestLedger(t, clock.Now)
			ctx := context.Background()
			d := digest(byte(0x40 + i))

			_, replay, err := led.Issue(ctx, "vault-a", d, 75, 2, 100,
				func(context.Context) (string, error) { return "", test.signErr })
			if !errors.Is(err, test.signErr) {
				t.Fatalf("issue error = %v, want %v", err, test.signErr)
			}
			if replay {
				t.Fatal("failed issuance reported as replay")
			}
			spent, err := led.SpentInPeriod(ctx, "vault-a", led.PeriodStart())
			if err != nil {
				t.Fatalf("spent after failure: %v", err)
			}
			if spent != 77 {
				t.Fatalf("post-submit failure reserved %d sats, want 77", spent)
			}
			if stored, ok, err := led.Completed(ctx, "vault-a", d); err != nil {
				t.Fatalf("completed lookup: %v", err)
			} else if ok || stored != "" {
				t.Fatalf("failed issuance persisted output %q", stored)
			}

			var retryCalls atomic.Int32
			if _, _, retryErr := led.Issue(ctx, "vault-a", d, 75, 2, 100,
				func(context.Context) (string, error) {
					retryCalls.Add(1)
					return "signed-after-retry", nil
				}); retryErr == nil {
				t.Fatal("post-submit failure allowed same-digest re-sign")
			}
			if retryCalls.Load() != 0 {
				t.Fatal("reserved digest reached the signer again")
			}
		})
	}
}

func TestCanceledClientAfterUsableSignatureCompletesIndependently(t *testing.T) {
	clock := newManualClock(time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC))
	led := openTestLedger(t, clock.Now)
	ctx, cancel := context.WithCancel(context.Background())
	d := digest(0x4e)

	// Model the uncertain external-signer window: the remote signer has received
	// the hot-signed transaction and produced a usable provider signature, then
	// the request context disappears before SQLite can record completion. The
	// external signer could already have retained or broadcast that transaction.
	escapedSignedPSBT := ""
	_, replay, err := led.Issue(ctx, "vault-a", d, 75, 2, 100,
		func(context.Context) (string, error) {
			escapedSignedPSBT = "signed-visible-to-external-signer"
			cancel()
			return escapedSignedPSBT, nil
		})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled client after usable signature: replay=%v err=%v", replay, err)
	}
	if escapedSignedPSBT == "" {
		t.Fatal("test did not reach the external-signature escape point")
	}

	spent, spentErr := led.SpentInPeriod(context.Background(), "vault-a", led.PeriodStart())
	if spentErr != nil {
		t.Fatalf("spent after canceled client: %v", spentErr)
	}
	if spent != 77 {
		t.Fatalf("usable signature after cancel reserved %d sats, want 77", spent)
	}

	var signerCalls atomic.Int32
	signed, replay, retryErr := led.Issue(
		context.Background(), "vault-a", d, 75, 2, 100,
		func(context.Context) (string, error) {
			signerCalls.Add(1)
			return "must-not-resign-uncertain-digest", nil
		},
	)
	if retryErr != nil || !replay || signed != escapedSignedPSBT {
		t.Fatalf("retry after independent complete: signed=%q replay=%v err=%v", signed, replay, retryErr)
	}
	if got := signerCalls.Load(); got != 0 {
		t.Fatalf("completed digest reached signer %d times", got)
	}
}

func TestEmptySignerOutputLeavesDurableReservation(t *testing.T) {
	clock := newManualClock(time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC))
	led := openTestLedger(t, clock.Now)
	ctx := context.Background()
	d := digest(0x4f)

	signed, replay, err := led.Issue(ctx, "vault-a", d, 75, 2, 100,
		func(context.Context) (string, error) { return "", nil })
	if err == nil {
		t.Fatal("empty signer output was committed")
	}
	if signed != "" || replay {
		t.Fatalf("empty signer output: signed=%q replay=%v err=%v", signed, replay, err)
	}
	spent, err := led.SpentInPeriod(ctx, "vault-a", led.PeriodStart())
	if err != nil {
		t.Fatalf("spent after empty output: %v", err)
	}
	if spent != 77 {
		t.Fatalf("empty post-submit output reserved %d sats, want 77", spent)
	}
	if stored, ok, err := led.Completed(ctx, "vault-a", d); err != nil {
		t.Fatalf("completed lookup: %v", err)
	} else if ok || stored != "" {
		t.Fatalf("empty signer output persisted as %q", stored)
	}

	var retryCalls atomic.Int32
	if _, _, retryErr := led.Issue(ctx, "vault-a", d, 75, 2, 100,
		func(context.Context) (string, error) {
			retryCalls.Add(1)
			return "signed-after-empty-output", nil
		}); retryErr == nil {
		t.Fatal("empty post-submit output allowed same-digest re-sign")
	}
	if retryCalls.Load() != 0 {
		t.Fatal("reserved digest reached the signer again")
	}
}

func TestExactIdempotentRetryReturnsPersistedOutputWithoutResigning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "idempotency.sqlite")
	clock := newManualClock(time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC))
	led, err := OpenLedger(path, clock.Now)
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	ctx := context.Background()
	d := digest(0x50)
	var signerCalls atomic.Int32

	signed, replay, err := led.Issue(ctx, "vault-a", d, 40, 3, 100,
		func(context.Context) (string, error) {
			signerCalls.Add(1)
			return "persisted-signed-psbt", nil
		})
	if err != nil || replay || signed != "persisted-signed-psbt" {
		t.Fatalf("initial issue: signed=%q replay=%v err=%v", signed, replay, err)
	}
	if err := led.Close(); err != nil {
		t.Fatalf("close ledger: %v", err)
	}

	led, err = OpenLedger(path, clock.Now)
	if err != nil {
		t.Fatalf("reopen ledger: %v", err)
	}
	t.Cleanup(func() {
		if err := led.Close(); err != nil {
			t.Errorf("close reopened ledger: %v", err)
		}
	})
	signed, replay, err = led.Issue(ctx, "vault-a", d, 40, 3, 100,
		func(context.Context) (string, error) {
			signerCalls.Add(1)
			return "must-not-replace-output", nil
		})
	if err != nil || !replay || signed != "persisted-signed-psbt" {
		t.Fatalf("idempotent retry: signed=%q replay=%v err=%v", signed, replay, err)
	}
	if got := signerCalls.Load(); got != 1 {
		t.Fatalf("signer calls = %d, want 1", got)
	}
	spent, err := led.SpentInPeriod(ctx, "vault-a", led.PeriodStart())
	if err != nil {
		t.Fatalf("spent: %v", err)
	}
	if spent != 43 {
		t.Fatalf("retry debited allowance twice: spent=%d", spent)
	}
	stored, ok, err := led.Completed(ctx, "vault-a", d)
	if err != nil || !ok || stored != "persisted-signed-psbt" {
		t.Fatalf("completed output: stored=%q ok=%v err=%v", stored, ok, err)
	}
}

func TestSameDigestIsNamespacedByVault(t *testing.T) {
	clock := newManualClock(time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC))
	led := openTestLedger(t, clock.Now)
	ctx := context.Background()
	d := digest(0x60)

	for _, test := range []struct {
		vault  string
		amount int64
		output string
	}{
		{vault: "vault-a", amount: 70, output: "signed-a"},
		{vault: "vault-b", amount: 80, output: "signed-b"},
	} {
		signed, replay, err := led.Issue(ctx, test.vault, d, test.amount, 1, 100,
			func(context.Context) (string, error) { return test.output, nil })
		if err != nil || replay || signed != test.output {
			t.Fatalf("issue %s: signed=%q replay=%v err=%v", test.vault, signed, replay, err)
		}
	}

	for _, test := range []struct {
		vault  string
		spent  int64
		output string
	}{
		{vault: "vault-a", spent: 71, output: "signed-a"},
		{vault: "vault-b", spent: 81, output: "signed-b"},
	} {
		spent, err := led.SpentInPeriod(ctx, test.vault, led.PeriodStart())
		if err != nil || spent != test.spent {
			t.Fatalf("spent for %s = %d, err=%v; want %d", test.vault, spent, err, test.spent)
		}
		stored, ok, err := led.Completed(ctx, test.vault, d)
		if err != nil || !ok || stored != test.output {
			t.Fatalf("completed for %s: stored=%q ok=%v err=%v", test.vault, stored, ok, err)
		}
	}
}

func TestReservedIssuanceCountsAgainstAllowanceAndCannotBeReissued(t *testing.T) {
	clock := newManualClock(time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC))
	led := openTestLedger(t, clock.Now)
	ctx := context.Background()
	reservedDigest := digest(0x70)
	_, err := led.db.Exec(
		`INSERT INTO issuance
		 (vault_id, arkade_sighash, period_start, recipient_amount, fee, state, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"vault-a", reservedDigest, led.PeriodStart(), 60, 1, stateReserved, clock.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		t.Fatalf("seed reserved issuance: %v", err)
	}

	spent, err := led.SpentInPeriod(ctx, "vault-a", led.PeriodStart())
	if err != nil || spent != 61 {
		t.Fatalf("reserved spend = %d, err=%v; want 61", spent, err)
	}
	if stored, ok, err := led.Completed(ctx, "vault-a", reservedDigest); err != nil {
		t.Fatalf("completed lookup: %v", err)
	} else if ok || stored != "" {
		t.Fatalf("reserved issuance exposed completed output %q", stored)
	}

	var signerCalls atomic.Int32
	sign := func(context.Context) (string, error) {
		signerCalls.Add(1)
		return "must-not-sign", nil
	}
	if _, _, err := led.Issue(ctx, "vault-a", reservedDigest, 60, 1, 100, sign); err == nil {
		t.Fatal("reserved digest was issued a second time")
	} else if !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("reserved retry returned unexpected error: %v", err)
	}
	if _, _, err := led.Issue(ctx, "vault-a", digest(0x71), 50, 1, 100, sign); err == nil {
		t.Fatal("a second issuance ignored the active reservation")
	} else if !strings.Contains(err.Error(), "allowance") {
		t.Fatalf("allowance rejection returned unexpected error: %v", err)
	}
	if got := signerCalls.Load(); got != 0 {
		t.Fatalf("signer called %d times for rejected reservations", got)
	}
}

func TestEnrollRejectsInvalidCredentialRecords(t *testing.T) {
	valid := validCredential(0x31)
	tests := []struct {
		name       string
		credential Credential
	}{
		{name: "empty credential id", credential: Credential{ID: []byte{}, WebAuthnP256: valid.WebAuthnP256, RPID: valid.RPID, Origin: valid.Origin}},
		{name: "short P-256 key", credential: Credential{ID: valid.ID, WebAuthnP256: valid.WebAuthnP256[:32], RPID: valid.RPID, Origin: valid.Origin}},
		{name: "invalid P-256 prefix", credential: Credential{ID: valid.ID, WebAuthnP256: bytes.Repeat([]byte{0x04}, 33), RPID: valid.RPID, Origin: valid.Origin}},
		{name: "reused webauthn key as direct-auth", credential: func() Credential {
			c := valid
			c.DirectP256 = append([]byte(nil), valid.WebAuthnP256...)
			return c
		}()},
		{name: "missing direct-auth p256", credential: func() Credential {
			c := valid
			c.DirectP256 = nil
			return c
		}()},
		{name: "short hot key", credential: Credential{ID: valid.ID, WebAuthnP256: valid.WebAuthnP256, Hot: valid.Hot[:32], RPID: valid.RPID, Origin: valid.Origin}},
		{name: "invalid hot key prefix", credential: Credential{ID: valid.ID, WebAuthnP256: valid.WebAuthnP256, Hot: bytes.Repeat([]byte{0x04}, 33), RPID: valid.RPID, Origin: valid.Origin}},
		{name: "empty RP ID", credential: Credential{ID: valid.ID, WebAuthnP256: valid.WebAuthnP256, RPID: "", Origin: valid.Origin}},
		{name: "empty origin", credential: Credential{ID: valid.ID, WebAuthnP256: valid.WebAuthnP256, RPID: valid.RPID, Origin: ""}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			led := openTestLedger(t, nil)
			if err := led.Enroll(test.credential); err == nil {
				t.Fatal("invalid credential was persisted")
			}
			got, err := led.GetCredential()
			if err != nil {
				t.Fatalf("get credential: %v", err)
			}
			if got != nil {
				t.Fatalf("invalid credential remained stored: %+v", got)
			}
		})
	}
}

func TestIssueRejectsInvalidLedgerInputsBeforeCallingSigner(t *testing.T) {
	tests := []struct {
		name      string
		vaultID   string
		digest    []byte
		recipient int64
		fee       int64
		cap       int64
		sign      AuthorizeFn
	}{
		{name: "empty vault id", vaultID: "", digest: digest(0x80), recipient: 1, fee: 0, cap: 100},
		{name: "empty digest", vaultID: "vault-a", digest: []byte{}, recipient: 1, fee: 0, cap: 100},
		{name: "short digest", vaultID: "vault-a", digest: digest(0x81)[:31], recipient: 1, fee: 0, cap: 100},
		{name: "long digest", vaultID: "vault-a", digest: append(digest(0x82), 0), recipient: 1, fee: 0, cap: 100},
		{name: "zero recipient", vaultID: "vault-a", digest: digest(0x83), recipient: 0, fee: 0, cap: 100},
		{name: "negative recipient", vaultID: "vault-a", digest: digest(0x84), recipient: -1, fee: 0, cap: 100},
		{name: "negative fee", vaultID: "vault-a", digest: digest(0x85), recipient: 1, fee: -1, cap: 100},
		{name: "negative allowance", vaultID: "vault-a", digest: digest(0x86), recipient: 1, fee: 0, cap: -1},
		{name: "nil signer", vaultID: "vault-a", digest: digest(0x87), recipient: 1, fee: 0, cap: 100, sign: nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			led := openTestLedger(t, nil)
			var signerCalls atomic.Int32
			sign := test.sign
			if test.name != "nil signer" {
				sign = func(context.Context) (string, error) {
					signerCalls.Add(1)
					return "must-not-sign", nil
				}
			}

			var issueErr error
			var panicked any
			func() {
				defer func() { panicked = recover() }()
				_, _, issueErr = led.Issue(
					context.Background(), test.vaultID, test.digest,
					test.recipient, test.fee, test.cap, sign,
				)
			}()
			if panicked != nil {
				t.Fatalf("Issue panicked instead of rejecting input: %v", panicked)
			}
			if issueErr == nil {
				t.Fatal("invalid input was accepted")
			}
			if got := signerCalls.Load(); got != 0 {
				t.Fatalf("signer called %d times for invalid input", got)
			}
			spent, err := led.SpentInPeriod(context.Background(), test.vaultID, led.PeriodStart())
			if err != nil {
				t.Fatalf("spent lookup: %v", err)
			}
			if spent != 0 {
				t.Fatalf("invalid issue changed allowance by %d", spent)
			}
		})
	}
}

func TestAllowanceAdditionCannotOverflow(t *testing.T) {
	led := openTestLedger(t, nil)
	ctx := context.Background()
	if _, _, err := led.Issue(
		ctx, "overflow-vault", digest(0x91), math.MaxInt64, 0, math.MaxInt64,
		func(context.Context) (string, error) { return "first-signed", nil },
	); err != nil {
		t.Fatalf("seed exact-cap issuance: %v", err)
	}

	var signerCalls atomic.Int32
	_, _, err := led.Issue(
		ctx, "overflow-vault", digest(0x92), 1, 0, math.MaxInt64,
		func(context.Context) (string, error) {
			signerCalls.Add(1)
			return "must-not-sign", nil
		},
	)
	if err == nil {
		t.Fatal("allowance check accepted recipient after int64 addition overflow")
	}
	if got := signerCalls.Load(); got != 0 {
		t.Fatalf("overflowing allowance request reached signer %d times", got)
	}
}
