package compose_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fakeDocker = `#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$FAKE_DOCKER_DIR/calls"

[ "$1" = exec ]
[ "$2" = arkd ]
shift 2
[ "$1" = timeout ]
[ "$2" = 15 ]
shift 2
[ "$1" = arkd ]
[ "$2" = wallet ]
shift 2

case "$1" in
  status)
    if [ "${FAKE_DOCKER_MODE:-}" = unavailable ]; then
      exit 1
    fi
    read initialized unlocked synced <"$FAKE_DOCKER_DIR/state"
    printf 'initialized: %s\nunlocked: %s\nsynced: %s\n' "$initialized" "$unlocked" "$synced"
    ;;
  create)
    [ "$2" = --password ]
    [ "$3" = "${EXPECTED_PASSWORD:?}" ]
    printf '%s\n' 'abandon ability able about above absent absorb abstract absurd abuse access accident'
    printf '%s\n' 'true false true' >"$FAKE_DOCKER_DIR/state"
    ;;
  unlock)
    [ "$2" = --password ]
    [ "$3" = "${EXPECTED_PASSWORD:?}" ]
    printf '%s\n' 'true true true' >"$FAKE_DOCKER_DIR/state"
    printf '%s\n' 'wallet unlocked'
    ;;
  *)
    exit 64
    ;;
esac
`

func TestArkdWalletBootstrapCreatesUnlocksAndIsRestartSafe(t *testing.T) {
	fixture := newWalletBootstrapFixture(t, "false false true")

	out, err := fixture.run()
	if err != nil {
		t.Fatalf("fresh bootstrap: %v\n%s", err, out)
	}
	if strings.Contains(out, "abandon ability") {
		t.Fatal("wallet mnemonic escaped into launcher output")
	}
	if !strings.Contains(out, "initialized, unlocked, and synced") {
		t.Fatalf("bootstrap did not report readiness:\n%s", out)
	}
	assertCallCounts(t, fixture.calls(t), 1, 1)

	// Running the launcher against an already-ready stack must be a no-op.
	out, err = fixture.run()
	if err != nil {
		t.Fatalf("idempotent bootstrap: %v\n%s", err, out)
	}
	assertCallCounts(t, fixture.calls(t), 1, 1)

	// A restarted wallet retains initialization but must be unlocked again.
	fixture.writeState(t, "true false true")
	out, err = fixture.run()
	if err != nil {
		t.Fatalf("restart bootstrap: %v\n%s", err, out)
	}
	assertCallCounts(t, fixture.calls(t), 1, 2)
}

func TestArkdWalletBootstrapBoundsUnavailableAdminWait(t *testing.T) {
	fixture := newWalletBootstrapFixture(t, "false false false")
	fixture.extraEnv = append(fixture.extraEnv,
		"FAKE_DOCKER_MODE=unavailable",
		"ARKD_REGTEST_WALLET_TRIES=2",
		"ARKD_REGTEST_WALLET_SLEEP=0",
	)

	started := time.Now()
	out, err := fixture.run()
	if err == nil {
		t.Fatalf("unavailable admin unexpectedly succeeded:\n%s", out)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("bounded two-attempt failure took %s", elapsed)
	}
	if !strings.Contains(out, "did not become initialized, unlocked, and synced after 2 attempts") {
		t.Fatalf("missing bounded-wait diagnostic:\n%s", out)
	}
	if got := strings.Count(fixture.calls(t), "arkd wallet status"); got != 2 {
		t.Fatalf("status attempts = %d, want 2", got)
	}
}

type walletBootstrapFixture struct {
	t        *testing.T
	dir      string
	script   string
	extraEnv []string
}

func newWalletBootstrapFixture(t *testing.T, state string) *walletBootstrapFixture {
	t.Helper()
	dir := t.TempDir()
	docker := filepath.Join(dir, "docker")
	if err := os.WriteFile(docker, []byte(fakeDocker), 0o700); err != nil {
		t.Fatal(err)
	}
	f := &walletBootstrapFixture{
		t:      t,
		dir:    dir,
		script: filepath.Join("scripts", "arkd-wallet-bootstrap.sh"),
	}
	f.writeState(t, state)
	return f
}

func (f *walletBootstrapFixture) run() (string, error) {
	f.t.Helper()
	cmd := exec.Command("sh", f.script)
	cmd.Env = append(os.Environ(),
		"PATH="+f.dir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_DOCKER_DIR="+f.dir,
		"EXPECTED_PASSWORD=arkade-regtest-only-wallet-fixture",
		"ARKD_REGTEST_WALLET_SLEEP=0",
	)
	cmd.Env = append(cmd.Env, f.extraEnv...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (f *walletBootstrapFixture) writeState(t *testing.T, state string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, "state"), []byte(state+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *walletBootstrapFixture) calls(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(f.dir, "calls"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func assertCallCounts(t *testing.T, calls string, creates, unlocks int) {
	t.Helper()
	if got := strings.Count(calls, "arkd wallet create"); got != creates {
		t.Fatalf("create calls = %d, want %d\n%s", got, creates, calls)
	}
	if got := strings.Count(calls, "arkd wallet unlock"); got != unlocks {
		t.Fatalf("unlock calls = %d, want %d\n%s", got, unlocks, calls)
	}
}
