package compose_test

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestMutinynetComposeSealsVaultCosignerKeyBehindGateway(t *testing.T) {
	base := mustDeploymentFile(t, "docker-compose.mutinynet.yml")
	enroll := mustDeploymentFile(t, "docker-compose.mutinynet.enroll.yml")
	dockerfile := mustDeploymentFile(t, "Dockerfile.mutinynet")
	gatewayDockerfile := mustDeploymentFile(t, "Dockerfile.gateway")
	caddy := mustDeploymentFile(t, "deploy/mutinynet/Caddyfile")
	runbook := mustDeploymentFile(t, "deploy/mutinynet/README.md")
	dockerignore := mustDeploymentFile(t, "../../.dockerignore")
	deploymentConfig := mustDeploymentFile(t, "internal/deployment/config.go")

	if got, want := composeServiceNames(base), []string{"vault-authorizer", "vault-gateway"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Mutinynet services = %v, want %v", got, want)
	}
	for _, forbidden := range []string{"VAULT_EMULATOR", "VAULT_ARKADE_EMULATOR", "unsafe-local-signer", "\n  emulator:", "\n  arkade-emulator:", "\n  arkd:"} {
		if strings.Contains(base, forbidden) || strings.Contains(caddy, forbidden) {
			t.Fatalf("Mutinynet topology contains forbidden local or operator-overridable signer dependency %q", forbidden)
		}
	}
	for _, pin := range []string{
		`MutinynetArkadeCosignerOrigin  = "https://emulator.mutinynet.arkade.sh"`,
		`MutinynetArkadeCosignerPubHex  = "03f823b9b2febc81f4af967e77aed2f541cbd3397c6d8f5a72e32eb7b471af889a"`,
		`MutinynetArkadeCosignerVersion = "v0.0.7-rc.1"`,
	} {
		if !strings.Contains(deploymentConfig, pin) {
			t.Fatalf("reviewed public Arkade cosigner release pin missing %q", pin)
		}
	}

	authorizer := between(t, base, "  vault-authorizer:\n", "\n  vault-gateway:")
	gateway := between(t, base, "  vault-gateway:\n", "\nnetworks:")
	for _, required := range []string{
		"-vault-cosigner-key-file=/run/secrets/vault_cosigner_key",
		"VAULT_EXTERNAL_OWNER_WALLET_PUB:",
		"vault-authorizer-data:/app/data",
		"vault-boundary",
		"ipv4_address: 172.30.44.10",
		"-addr=172.30.44.10:8788",
		"vault-egress",
		"read_only: true",
		"cap_drop:",
		"driver: local",
		"max-size: \"10m\"",
		"max-file: \"3\"",
	} {
		if !strings.Contains(authorizer, required) {
			t.Fatalf("authorizer missing %q", required)
		}
	}
	if strings.Contains(authorizer, "\n    ports:") {
		t.Fatal("authorizer must not publish a host port")
	}
	for _, forbidden := range []string{"vault_cosigner_key", "vault-authorizer-data", "/app/data", "VAULT_ENROLLMENT_TOKEN", "VAULT_EXTERNAL_OWNER_WALLET_PUB", "VAULT_RECOVERY_KEY_PUB"} {
		if strings.Contains(gateway, forbidden) {
			t.Fatalf("stateless gateway owns protected state %q", forbidden)
		}
	}
	if !strings.Contains(gateway, "Dockerfile.gateway") || !strings.Contains(gateway, "\"443:443\"") {
		t.Fatal("gateway is not a pinned public TLS endpoint")
	}
	for _, required := range []string{"read_only: true", "cap_drop:\n      - ALL", "no-new-privileges:true", "pids_limit: 128", "net.ipv4.ip_unprivileged_port_start: 0", "driver: local", "max-size: \"10m\"", "max-file: \"3\""} {
		if !strings.Contains(gateway, required) {
			t.Fatalf("gateway hardening missing %q", required)
		}
	}
	if !strings.Contains(gatewayDockerfile, "FROM caddy:2.11.4-alpine") || !strings.Contains(gatewayDockerfile, "USER 10002:10002") {
		t.Fatal("gateway image must pin Caddy and run as a dedicated non-root user")
	}
	for _, digest := range []string{
		"golang:1.26.6@sha256:640a234f4bea3e399c056b7b8f9c667c4939befae8db2f14e9785e16eccd4205",
		"alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b",
		"caddy:2.11.4-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648",
	} {
		if !strings.Contains(dockerfile+gatewayDockerfile, digest) {
			t.Fatalf("deployment base image is not digest-pinned: %s", digest)
		}
	}
	for _, required := range []string{"web/index.html", "web/app.js", "web/authorizeretry.js", "web/psbtcheck.js", "web/vendor/btc-signer.js", "web/vendor/NOTICE.md"} {
		if !strings.Contains(gatewayDockerfile, required) {
			t.Fatalf("gateway image missing runtime asset %q", required)
		}
	}
	for _, forbidden := range []string{"COPY --chown=10002:10002 poc/2fa-vault/web /srv", ".test.js", "web/e2e", "vendor/rebuild.sh"} {
		if strings.Contains(gatewayDockerfile, forbidden) {
			t.Fatalf("gateway image publishes non-runtime browser asset %q", forbidden)
		}
	}
	if !strings.Contains(base, "vault-boundary:\n    internal: true") {
		t.Fatal("gateway-to-authorizer network must be internal")
	}
	if !strings.Contains(authorizer, "vault-egress:\n        # Compose >=2.33.1") || !strings.Contains(authorizer, "gw_priority: 1") {
		t.Fatal("authorizer Esplora egress must be the explicit default gateway")
	}
	if !strings.Contains(gateway, "vault-edge:\n        gw_priority: 1") {
		t.Fatal("gateway ACME egress must be the explicit default gateway")
	}
	if strings.Contains(base, "VAULT_ENROLLMENT_TOKEN_FILE") || strings.Contains(base, "vault_enrollment_token") {
		t.Fatal("base restart topology must not require the consumed enrollment token")
	}
	if !strings.Contains(enroll, "VAULT_ENROLLMENT_TOKEN_FILE: /run/secrets/vault_enrollment_token") || !strings.Contains(enroll, "first enrollment only") {
		t.Fatal("one-time enrollment overlay is incomplete")
	}
	if !strings.Contains(dockerfile, "./poc/2fa-vault/cmd/authorizer") || strings.Contains(dockerfile, "cmd/provider") || strings.Contains(dockerfile, "COPY poc/2fa-vault/web") {
		t.Fatal("authorizer image must build only the protected command and contain no web client")
	}
	for _, pattern := range []string{".env.*", "*.key", "*.secret", "provider-key", "enrollment-token", "**/secrets/", "poc/2fa-vault/testdata/webauthn_get.json", "poc/2fa-vault/testdata/chrome-*"} {
		if !strings.Contains(dockerignore, pattern) {
			t.Fatalf("Docker build context does not exclude secret pattern %q", pattern)
		}
	}
	for _, required := range []string{"chmod 0600", "UID 10001", "uid/gid/mode", "0700"} {
		if !strings.Contains(runbook, required) {
			t.Fatalf("runbook does not explain portable non-root file-secret access: missing %q", required)
		}
	}

	for _, required := range []string{
		"request_body {\n\t\tmax_size 1MB",
		"Cache-Control \"no-store\"",
		"request>headers>X-Vault-Enrollment-Token delete",
		"method GET\n\t\tpath /v1/status /v1/tx /v1/invite",
		"method POST\n\t\tpath /v1/preflight /v1/draft /v1/bind /v1/authorize /v1/publish /v1/enroll/start /v1/enroll/propose /v1/enroll/finish /v1/passkey/challenge /v1/passkey/binding /v1/passkey/install /v1/passkey/recover",
		"method OPTIONS\n\t\tpath /v1/status /v1/invite /v1/preflight /v1/draft /v1/bind /v1/authorize /v1/publish /v1/tx /v1/enroll/start /v1/enroll/propose /v1/enroll/finish /v1/passkey/challenge /v1/passkey/binding /v1/passkey/install /v1/passkey/recover",
		"@any_v1 {\n\t\tpath /v1/*\n\t}\n\thandle @any_v1 {\n\t\trespond \"not found\" 404",
	} {
		if !strings.Contains(caddy, required) {
			t.Fatalf("gateway route allowlist missing %q", required)
		}
	}
	for _, forbidden := range []string{"/v1/sign", "/v1/onchain-tx", "/v1/demo/", "/v1/register"} {
		if strings.Contains(caddy, forbidden) {
			t.Fatalf("gateway contains forbidden route %q", forbidden)
		}
	}
}

func TestMutinynetImageReadsFileSecretAsNonRoot(t *testing.T) {
	if os.Getenv("VAULT_TEST_DOCKER") != "1" {
		t.Skip("set VAULT_TEST_DOCKER=1 for the built-container secret smoke test")
	}
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}
	// Colima/Docker Desktop may not share the host's system temp directory.
	// Put the ephemeral mount beside the repo, under the already shared /Users
	// tree, but outside the Docker build context and Git worktree.
	secretDir, err := os.MkdirTemp(filepath.Dir(repoRoot), ".vault-secret-smoke-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(secretDir) })
	if err := os.Chmod(secretDir, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(secretDir, "vault-cosigner-key")
	if err := os.WriteFile(secret, []byte(strings.Repeat("2", 64)+"\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(secret, 0o444); err != nil {
		t.Fatal(err)
	}
	imageID := buildDockerImage(t, docker, repoRoot, "poc/2fa-vault/Dockerfile.mutinynet")
	mount := "type=bind,src=" + secret + ",dst=/run/secrets/vault_cosigner_key,readonly"
	run := exec.Command(docker, "run", "--rm", "--entrypoint", "/bin/sh", "--mount", mount, imageID,
		"-ec", "id -u | grep -qx 10001\ntest -r /run/secrets/vault_cosigner_key\nwc -c /run/secrets/vault_cosigner_key | grep -q '^65 '")
	if output, err := run.CombinedOutput(); err != nil {
		t.Fatalf("non-root file-secret smoke: %v\n%s", err, output)
	}
}

func TestMutinynetGatewayImageContainsOnlyRuntimeAssets(t *testing.T) {
	if os.Getenv("VAULT_TEST_DOCKER") != "1" {
		t.Skip("set VAULT_TEST_DOCKER=1 for the built gateway asset smoke test")
	}
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}
	imageID := buildDockerImage(t, docker, repoRoot, "poc/2fa-vault/Dockerfile.gateway")
	run := exec.Command(docker, "run", "--rm", "--entrypoint", "/bin/sh", imageID,
		"-ec", "find /srv -type f -print | sort")
	output, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("list gateway assets: %v\n%s", err, output)
	}
	got := strings.Fields(string(output))
	want := []string{
		"/srv/app.css",
		"/srv/app.js",
		"/srv/authorizeretry.js",
		"/srv/directauth.js",
		"/srv/enrollstore.js",
		"/srv/index.html",
		"/srv/psbtcheck.js",
		"/srv/vendor/LICENSE.micro-packed",
		"/srv/vendor/LICENSE.noble-curves",
		"/srv/vendor/LICENSE.noble-hashes",
		"/srv/vendor/LICENSE.scure-base",
		"/srv/vendor/LICENSE.scure-btc-signer",
		"/srv/vendor/NOTICE.md",
		"/srv/vendor/btc-signer.js",
		"/srv/vendor/p256.js",
		"/srv/vendor/secp256k1.js",
		"/srv/webauthnkey.js",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("gateway /srv assets = %v, want %v", got, want)
	}
}

func buildDockerImage(t *testing.T, docker, repoRoot, dockerfile string) string {
	t.Helper()
	build := exec.Command(docker, "build", "--quiet", "-f", dockerfile, ".")
	build.Dir = repoRoot
	rawImage, err := build.CombinedOutput()
	if err != nil {
		t.Fatalf("build %s: %v\n%s", dockerfile, err, rawImage)
	}
	for _, field := range strings.Fields(string(rawImage)) {
		if strings.HasPrefix(field, "sha256:") {
			return field
		}
	}
	t.Fatalf("docker build %s returned no image id: %s", dockerfile, rawImage)
	return ""
}

func TestAuthorizerBinaryExcludesGenericOrGRPCSigningSurface(t *testing.T) {
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	list := exec.Command("go", "list", "-deps", "./poc/2fa-vault/cmd/authorizer")
	list.Dir = repoRoot
	deps, err := list.CombinedOutput()
	if err != nil {
		t.Fatalf("go list authorizer: %v\n%s", err, deps)
	}
	for _, forbidden := range []string{
		"github.com/arkade-os/emulator/pkg/client",
		"github.com/arkade-os/emulator/poc/2fa-vault/internal/remotesigner",
		// grpc/codes-family helpers remain through ark-lib error values. The
		// root client API and transport implementation must not be linked.
		"google.golang.org/grpc",
		"google.golang.org/grpc/internal/transport",
	} {
		if bytes.Contains(deps, []byte(forbidden+"\n")) {
			t.Fatalf("authorizer dependency graph contains %s", forbidden)
		}
	}

	binary := filepath.Join(t.TempDir(), "vault-authorizer")
	build := exec.Command("go", "build", "-trimpath", "-o", binary, "./poc/2fa-vault/cmd/authorizer")
	build.Dir = repoRoot
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build authorizer: %v\n%s", err, output)
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{
		[]byte("emulator.v1.EmulatorService/SubmitOnchainTx"),
		[]byte("NewEmulatorServiceClient"),
		[]byte("VAULT_EMULATOR"),
		[]byte("VAULT_ARKADE_EMULATOR"),
		[]byte("RemoteSigner"),
		[]byte("remote signer missing client"),
		[]byte("/v1/demo/fund"),
	} {
		if bytes.Contains(raw, forbidden) {
			t.Fatalf("authorizer binary contains regtest signer surface %q", forbidden)
		}
	}
	for _, required := range [][]byte{
		[]byte("https://emulator.mutinynet.arkade.sh"),
		[]byte("/v1/onchain-tx"),
	} {
		if !bytes.Contains(raw, required) {
			t.Fatalf("authorizer binary is missing narrow pinned outbound cosigner marker %q", required)
		}
	}
}

func mustDeploymentFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func composeServiceNames(raw string) []string {
	scanner := bufio.NewScanner(strings.NewReader(raw))
	inServices := false
	var names []string
	for scanner.Scan() {
		line := scanner.Text()
		if line == "services:" {
			inServices = true
			continue
		}
		if inServices && line != "" && line[0] != ' ' {
			break
		}
		if inServices && strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") && strings.HasSuffix(line, ":") {
			names = append(names, strings.TrimSuffix(strings.TrimSpace(line), ":"))
		}
	}
	sort.Strings(names)
	return names
}

func between(t *testing.T, raw, start, end string) string {
	t.Helper()
	from := strings.Index(raw, start)
	if from < 0 {
		t.Fatalf("missing section start %q", start)
	}
	from += len(start)
	to := strings.Index(raw[from:], end)
	if to < 0 {
		t.Fatalf("missing section end %q", end)
	}
	return raw[from : from+to]
}
