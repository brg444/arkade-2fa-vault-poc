package compose_test

import (
	"os"
	"strings"
	"testing"
)

func TestLiveAcceptanceIsExplicitScopedAndDurable(t *testing.T) {
	scriptRaw, err := os.ReadFile("scripts/live-acceptance.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(scriptRaw)
	for _, required := range []string{
		`VAULT_LIVE_ACCEPTANCE`,
		`COMPOSE_PROJECT_NAME`,
		`live-app.mjs`,
		`restart vault-provider`,
		`/v1/tx?challenge=`,
		`bitcoin-cli getrawtransaction`,
		`down -v`,
		`periodSpent`,
		`periodRemaining`,
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("live acceptance is missing %q", required)
		}
	}
	if strings.Contains(script, "nigiri stop") || strings.Contains(script, "nigiri delete") {
		t.Fatal("live acceptance must not stop or delete shared Nigiri state")
	}
	if strings.Contains(script, "--remove-orphans") || strings.Contains(script, "VAULT_E2E_PROJECT") {
		t.Fatal("live acceptance must use its internally generated project and must not remove orphans")
	}
	if !strings.Contains(script, `existing POC container`) {
		t.Fatal("live acceptance must refuse to collide with fixed POC containers")
	}
	runnerRaw, err := os.ReadFile("scripts/run-bounded.mjs")
	if err != nil {
		t.Fatal(err)
	}
	runner := string(runnerRaw)
	for _, required := range []string{`detached:`, `process.kill(-child.pid`, `waitForGroupExit`, `SIGTERM`, `SIGKILL`} {
		if !strings.Contains(runner, required) {
			t.Fatalf("bounded runner is missing process-group safeguard %q", required)
		}
	}

	makeRaw, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(makeRaw), "vault-regtest-e2e:") {
		t.Fatal("Makefile must expose vault-regtest-e2e")
	}

	browserRaw, err := os.ReadFile("web/e2e/live-app.mjs")
	if err != nil {
		t.Fatal(err)
	}
	contractRaw, err := os.ReadFile("web/e2e/live-contract.mjs")
	if err != nil {
		t.Fatal(err)
	}
	browser := string(browserRaw) + string(contractRaw)
	for _, required := range []string{
		`signerMode !== "remote"`,
		`remoteSignerSuccesses`,
		`/v1/demo/fund`,
		`/v1/authorize`,
		`/v1/publish`,
		`/v1/demo/mine`,
		`/v1/tx?challenge=`,
		`ARKADE_LIVE_RESULT=`,
	} {
		if !strings.Contains(browser, required) {
			t.Fatalf("live browser acceptance is missing %q", required)
		}
	}
	if strings.Contains(browser, "unsafe-local-signer") || strings.Contains(browser, "provider-key") {
		t.Fatal("live browser acceptance must not start or configure the unsafe signer")
	}
}
