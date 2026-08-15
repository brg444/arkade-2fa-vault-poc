package compose_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/arkade-os/emulator/poc/2fa-vault/fixture"
)

func TestVaultComposeOverlayBuildContextResolvesFromEmulatorRoot(t *testing.T) {
	overlay, err := os.ReadFile("docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(overlay)
	if !strings.Contains(text, "context: .") {
		t.Fatal("vault-provider build.context must be \".\" so the documented merge from emulator root can find poc/2fa-vault/Dockerfile")
	}
	if strings.Contains(text, "context: ../..") {
		t.Fatal("build.context ../.. resolves outside the emulator repo when docker-compose.regtest.yml is the first -f file")
	}
	if strings.Contains(text, "tmpfs") {
		t.Fatal("compose must persist provider data on a named volume, not tmpfs")
	}
	if !strings.Contains(text, "vault-provider-data") {
		t.Fatal("compose is missing named volume vault-provider-data")
	}
	if !strings.Contains(text, "VAULT_OFFLINE_PUB") || !strings.Contains(text, fixture.OfflinePubHex) {
		t.Fatal("compose must set the opaque known-valid VAULT_OFFLINE_PUB fixture")
	}
	if !strings.Contains(text, "127.0.0.1:8787:8787") {
		t.Fatal("UI port must remain loopback-only")
	}
	if hostPortCount(text) != 1 {
		t.Fatal("POC overlay must publish only 127.0.0.1:8787")
	}
	if strings.Contains(text, "7073:7073") || strings.Contains(text, "- 7073") {
		t.Fatal("overlay must not publish emulator 7073")
	}
	if !strings.Contains(text, "vault-signer:") || !strings.Contains(text, "internal: true") {
		t.Fatal("overlay must declare an internal vault-signer network")
	}
	if strings.Contains(text, "networks: !reset") {
		t.Fatal("emulator networks: !reset discards vault-signer and falls back to nigiri")
	}
	if !strings.Contains(text, "networks: !override") {
		t.Fatal("emulator must use networks: !override so the merged service keeps only vault-signer")
	}
	for _, svc := range []string{"arkd:", "arkd-wallet:", "nbxplorer:", "pgnbxplorer:"} {
		if !strings.Contains(text, svc) {
			t.Fatalf("overlay must mention %s so its host ports can be reset", svc)
		}
	}
	if strings.Count(text, "ports: !reset []") < 5 {
		t.Fatal("overlay must reset emulator and ark support host ports")
	}
	if !strings.Contains(text, "restart: unless-stopped") {
		t.Fatal("vault-provider must restart unless-stopped; depends_on does not mean emulator is ready")
	}
	if !strings.Contains(text, "VAULT_DEMO") || !strings.Contains(text, "VAULT_BITCOIN_RPC") {
		t.Fatal("POC compose must set gated demo funding and Bitcoin RPC for Publish")
	}

	script, err := os.ReadFile(filepath.Join("scripts", "regtest-up.sh"))
	if err != nil {
		t.Fatal(err)
	}
	sh := string(script)
	if strings.Contains(sh, "BITCOIN_EXTRA_ARGS") {
		t.Fatal("regtest-up.sh must not set BITCOIN_EXTRA_ARGS; Nigiri does not consume it")
	}
	if !strings.Contains(sh, "docker info") {
		t.Fatal("regtest-up.sh must fail early if the Docker daemon is unreachable")
	}
	if !strings.Contains(sh, "nigiri start --ci --ark=false --liquid=false --ln=false") {
		t.Fatal("regtest-up.sh must start Nigiri without official ark/liquid/ln")
	}
	if !strings.Contains(sh, "wait_nigiri_rpc") || !strings.Contains(sh, "getblockchaininfo") {
		t.Fatal("regtest-up.sh must poll nigiri rpc getblockchaininfo before treating Nigiri as absent")
	}
	if !strings.Contains(sh, "require_core30") || !strings.Contains(sh, "docker exec bitcoin bitcoin-cli getnetworkinfo") {
		t.Fatal("regtest-up.sh must read raw getnetworkinfo via docker exec bitcoin bitcoin-cli")
	}
	if strings.Contains(sh, "nigiri rpc getnetworkinfo") {
		t.Fatal("regtest-up.sh must not parse ANSI-colored nigiri rpc getnetworkinfo")
	}
	if !strings.Contains(sh, "300000") || !strings.Contains(sh, "-lt 300000") {
		t.Fatal("regtest-up.sh must require a numeric Bitcoin Core version >= 300000")
	}
	if !strings.Contains(sh, "117-byte") || !strings.Contains(sh, "83-byte") {
		t.Fatal("regtest-up.sh must explain the 117-byte packet vs the old 83-byte default")
	}
	if !strings.Contains(sh, "testmempoolaccept remains the authoritative custom-policy gate") {
		t.Fatal("regtest-up.sh must keep testmempoolaccept as the publish policy gate")
	}
	if strings.Contains(sh, "nigiri stop") || strings.Contains(sh, "nigiri abort") || strings.Contains(sh, "nigiri down") {
		t.Fatal("regtest-up.sh must not stop or delete user Nigiri state")
	}
	if !strings.Contains(sh, "already running") || !strings.Contains(sh, "stale or still warming") {
		t.Fatal("regtest-up.sh must fail clearly when Nigiri is already running but RPC stays unavailable")
	}
	if !strings.Contains(sh, "up -d --build") {
		t.Fatal("regtest-up.sh must start the stack detached")
	}
	if !strings.Contains(sh, "http://localhost:8787") {
		t.Fatal("regtest-up.sh must print the WebAuthn origin")
	}
	if !strings.Contains(sh, `emulator must have exactly one attached network`) {
		t.Fatal("regtest-up.sh must require emulator to have exactly one attached network")
	}
	if !strings.Contains(sh, "Internal=true") && !strings.Contains(sh, "{{.Internal}}") {
		t.Fatal("regtest-up.sh must require the emulator network Internal=true")
	}

	emulatorRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	dockerfile := filepath.Join(emulatorRoot, "poc", "2fa-vault", "Dockerfile")
	rawDockerfile, err := os.ReadFile(dockerfile)
	if err != nil {
		t.Fatalf("Dockerfile missing at merge-resolved path %s: %v", dockerfile, err)
	}
	df := string(rawDockerfile)
	if !strings.Contains(df, "golang:1.26.6") {
		t.Fatal("Dockerfile builder must pin golang:1.26.6")
	}
	if !strings.Contains(df, "./poc/2fa-vault/cmd/provider") || !strings.Contains(df, "vault-provider") {
		t.Fatal("Dockerfile must build and run cmd/provider as vault-provider")
	}
	if strings.Contains(df, "cmd/demo") {
		t.Fatal("deployment Dockerfile must not build cmd/demo")
	}
	if !strings.Contains(df, "-db") || !strings.Contains(df, "/app/data/vault.sqlite") {
		t.Fatal("Dockerfile entrypoint must pass -db /app/data/vault.sqlite")
	}

	makefile, err := os.ReadFile(filepath.Join(emulatorRoot, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	mk := string(makefile)
	if !strings.Contains(mk, "vault-demo:") || !strings.Contains(mk, "vault-demo-down:") {
		t.Fatal("Makefile must expose vault-demo and vault-demo-down")
	}
	if strings.Contains(mk, "poc/2fa-vault/docker-compose.yml down -v") {
		t.Fatal("vault-demo-down must preserve the named volume")
	}

	if os.Getenv("VAULT_TEST_DOCKER") != "1" {
		t.Log("skipping docker compose config/build; set VAULT_TEST_DOCKER=1 to run it")
		return
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("VAULT_TEST_DOCKER=1 but docker is not available: %v", err)
	}

	ctxArgs := []string{
		"compose",
		"-f", "docker-compose.regtest.yml",
		"-f", "poc/2fa-vault/docker-compose.yml",
	}
	config := exec.Command("docker", append(ctxArgs, "config", "--format", "json")...)
	config.Dir = emulatorRoot
	out, err := config.CombinedOutput()
	if err != nil {
		t.Fatalf("docker compose config --format json: %v\n%s", err, out)
	}
	assertMergedComposeJSON(t, out)

	build := exec.Command("docker", append(ctxArgs, "build", "vault-provider")...)
	build.Dir = emulatorRoot
	build.Env = os.Environ()
	out, err = build.CombinedOutput()
	if err != nil {
		t.Fatalf("docker compose build vault-provider: %v\n%s", err, out)
	}
}

func hostPortCount(overlay string) int {
	n := 0
	for _, line := range strings.Split(overlay, "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "#") {
			continue
		}
		if strings.Contains(trim, "127.0.0.1:") || strings.Contains(trim, "0.0.0.0:") {
			n++
		}
	}
	return n
}

type composeConfig struct {
	Services map[string]composeService `json:"services"`
	Networks map[string]composeNetwork `json:"networks"`
	Volumes  map[string]any            `json:"volumes"`
}

type composeService struct {
	Networks json.RawMessage      `json:"networks"`
	Ports    []composePort        `json:"ports"`
	Build    *composeBuild        `json:"build"`
	Volumes  []composeVolumeMount `json:"volumes"`
}

type composeVolumeMount struct {
	Type   string `json:"type"`
	Source string `json:"source"`
	Target string `json:"target"`
}

type composePort struct {
	HostIP    string `json:"host_ip"`
	Published any    `json:"published"`
	Target    int    `json:"target"`
}

type composeBuild struct {
	Dockerfile string `json:"dockerfile"`
	Context    string `json:"context"`
}

type composeNetwork struct {
	Name     string `json:"name"`
	Internal bool   `json:"internal"`
	External any    `json:"external"`
}

func assertMergedComposeJSON(t *testing.T, raw []byte) {
	t.Helper()
	if err := checkMergedComposeJSON(raw); err != nil {
		t.Fatal(err)
	}
}

func checkMergedComposeJSON(raw []byte) error {
	var cfg composeConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("compose config json: %w\n%s", err, raw)
	}
	em, ok := cfg.Services["emulator"]
	if !ok {
		return fmt.Errorf("merged compose is missing emulator")
	}
	emNets, err := networkSet("emulator", em.Networks)
	if err != nil {
		return err
	}
	if strings.Join(emNets, ",") != "vault-signer" {
		return fmt.Errorf("rendered emulator networks = %v, want exactly [vault-signer]", emNets)
	}
	if len(em.Ports) > 0 {
		return fmt.Errorf("emulator must not publish host ports: %+v", em.Ports)
	}

	signer, ok := cfg.Networks["vault-signer"]
	if !ok || !signer.Internal {
		return fmt.Errorf("vault-signer must be internal: %+v", signer)
	}
	if signer.Name == "vault-signer" {
		return fmt.Errorf("rendered vault-signer must not use a global explicit name")
	}
	if def, ok := cfg.Networks["default"]; ok {
		if networkName(def) != "nigiri" {
			return fmt.Errorf("default network name = %q, want nigiri", networkName(def))
		}
	}

	arkd, ok := cfg.Services["arkd"]
	if !ok {
		return fmt.Errorf("merged compose is missing arkd")
	}
	arkdNets, err := networkSet("arkd", arkd.Networks)
	if err != nil {
		return err
	}
	if !hasAll(arkdNets, "default", "vault-signer") {
		return fmt.Errorf("arkd networks = %v, want default and vault-signer", arkdNets)
	}
	if len(arkd.Ports) > 0 {
		return fmt.Errorf("arkd must not publish host ports: %+v", arkd.Ports)
	}

	prov, ok := cfg.Services["vault-provider"]
	if !ok {
		return fmt.Errorf("merged compose is missing vault-provider")
	}
	provNets, err := networkSet("vault-provider", prov.Networks)
	if err != nil {
		return err
	}
	if !hasAll(provNets, "default", "vault-signer") {
		return fmt.Errorf("vault-provider networks = %v, want default and vault-signer", provNets)
	}
	if prov.Build == nil || !strings.Contains(prov.Build.Dockerfile, "poc/2fa-vault/Dockerfile") {
		return fmt.Errorf("vault-provider dockerfile = %+v", prov.Build)
	}
	if _, ok := cfg.Volumes["vault-provider-data"]; !ok {
		return fmt.Errorf("merged compose is missing named volume vault-provider-data")
	}
	foundData := false
	for _, vol := range prov.Volumes {
		if vol.Target != "/app/data" {
			continue
		}
		foundData = true
		if vol.Type != "" && vol.Type != "volume" {
			return fmt.Errorf("vault-provider /app/data type = %q, want named volume", vol.Type)
		}
		if vol.Source != "vault-provider-data" {
			return fmt.Errorf("vault-provider /app/data source = %q, want vault-provider-data", vol.Source)
		}
	}
	if !foundData {
		return fmt.Errorf("vault-provider /app/data must be a named volume sourced from vault-provider-data")
	}

	var published []composePort
	for name, svc := range cfg.Services {
		for _, p := range svc.Ports {
			if p.Published == nil || p.Published == "" || p.Published == 0 {
				continue
			}
			published = append(published, p)
			if name != "vault-provider" || p.HostIP != "127.0.0.1" || p.Target != 8787 {
				return fmt.Errorf("unexpected host publish on %s: %+v", name, p)
			}
		}
	}
	if len(published) != 1 {
		return fmt.Errorf("merged compose host publishes = %+v, want only 127.0.0.1:8787", published)
	}
	return nil
}

func networkSet(svc string, raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, fmt.Errorf("%s rendered networks are empty", svc)
	}
	var asMap map[string]any
	if err := json.Unmarshal(raw, &asMap); err == nil {
		out := make([]string, 0, len(asMap))
		for k := range asMap {
			out = append(out, k)
		}
		sort.Strings(out)
		return out, nil
	}
	var asList []string
	if err := json.Unmarshal(raw, &asList); err == nil {
		sort.Strings(asList)
		return asList, nil
	}
	return nil, fmt.Errorf("%s rendered networks are not a JSON object or string list: %s", svc, raw)
}

func hasAll(got []string, want ...string) bool {
	have := map[string]bool{}
	for _, n := range got {
		have[n] = true
	}
	for _, n := range want {
		if !have[n] {
			return false
		}
	}
	return true
}

func networkName(n composeNetwork) string {
	if n.Name != "" {
		return n.Name
	}
	return ""
}

func TestMergedComposeJSONRequiresProjectScopedSignerAndNamedVolume(t *testing.T) {
	raw := []byte(`{
		"services": {
			"emulator": {"networks": {"vault-signer": null}, "ports": []},
			"arkd": {"networks": {"default": null, "vault-signer": null}, "ports": []},
			"vault-provider": {
				"networks": {"default": null, "vault-signer": null},
				"ports": [{"host_ip": "127.0.0.1", "published": "8787", "target": 8787}],
				"build": {"dockerfile": "poc/2fa-vault/Dockerfile"},
				"volumes": [{"type": "volume", "source": "vault-provider-data", "target": "/app/data"}]
			}
		},
		"networks": {
			"default": {"name": "nigiri", "external": true},
			"vault-signer": {"internal": true}
		},
		"volumes": {"vault-provider-data": {}}
	}`)
	assertMergedComposeJSON(t, raw)

	bind := []byte(`{
		"services": {
			"emulator": {"networks": {"vault-signer": null}},
			"arkd": {"networks": {"default": null, "vault-signer": null}},
			"vault-provider": {
				"networks": {"default": null, "vault-signer": null},
				"ports": [{"host_ip": "127.0.0.1", "published": "8787", "target": 8787}],
				"build": {"dockerfile": "poc/2fa-vault/Dockerfile"},
				"volumes": [{"type": "bind", "source": "./data", "target": "/app/data"}]
			}
		},
		"networks": {"vault-signer": {"internal": true}},
		"volumes": {"vault-provider-data": {}}
	}`)
	if err := checkMergedComposeJSON(bind); err == nil {
		t.Fatal("bind-mounted /app/data accepted")
	}

	global := []byte(`{
		"services": {
			"emulator": {"networks": {"vault-signer": null}},
			"arkd": {"networks": {"default": null, "vault-signer": null}},
			"vault-provider": {
				"networks": {"default": null, "vault-signer": null},
				"ports": [{"host_ip": "127.0.0.1", "published": "8787", "target": 8787}],
				"build": {"dockerfile": "poc/2fa-vault/Dockerfile"},
				"volumes": [{"type": "volume", "source": "vault-provider-data", "target": "/app/data"}]
			}
		},
		"networks": {"vault-signer": {"name": "vault-signer", "internal": true}},
		"volumes": {"vault-provider-data": {}}
	}`)
	if err := checkMergedComposeJSON(global); err == nil {
		t.Fatal("global vault-signer name accepted")
	}
}

const launcherCoreVersionParse = `tr ',' '\n' | sed -n 's/.*"version"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n 1`

func TestLauncherParsesGetNetworkInfoVersion(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("scripts", "regtest-up.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(script), launcherCoreVersionParse) {
		t.Fatal("regtest-up.sh must parse getnetworkinfo version with the tested pipeline")
	}
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(readme)
	if !strings.Contains(doc, "docker exec bitcoin bitcoin-cli getnetworkinfo") || !strings.Contains(doc, "300000") {
		t.Fatal("README must document the raw bitcoin-cli Core 30+ launcher gate")
	}
	if !strings.Contains(doc, "testmempoolaccept") {
		t.Fatal("README must keep testmempoolaccept as the publish policy gate")
	}

	cases := []struct {
		in     string
		want   string
		accept bool
	}{
		{`{ "version": 300000, "protocolversion": 70016 }`, "300000", true},
		{"{\n  \"version\": 300000,\n  \"subversion\": \"/Satoshi:30.0.0/\"\n}", "300000", true},
		{`{"version":250000,"protocolversion":70016}`, "250000", false},
		{`{"version":299999}`, "299999", false},
		{`{"protocolversion":70016,"subversion":"/Satoshi:30.0.0/"}`, "", false},
		{`{"version":"30.0.0"}`, "", false},
		// Nigiri `rpc` wraps keys/values in aurora ANSI. That is not the
		// launcher input; bitcoin-cli raw JSON is. Colored text must not
		// be treated as a valid version field.
		{"\x1b[94m\"version\"\x1b[0m: \x1b[96m300000\x1b[0m", "", false},
	}
	for _, tc := range cases {
		got := parseLauncherCoreVersion(t, tc.in)
		if got != tc.want {
			t.Fatalf("parse %q = %q, want %q", tc.in, got, tc.want)
		}
		if ok := coreVersionAccepted(got); ok != tc.accept {
			t.Fatalf("accept %q = %v, want %v", got, ok, tc.accept)
		}
	}
}

func parseLauncherCoreVersion(t *testing.T, raw string) string {
	t.Helper()
	cmd := exec.Command("sh", "-c", launcherCoreVersionParse)
	cmd.Stdin = strings.NewReader(raw)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("parse pipeline: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func coreVersionAccepted(ver string) bool {
	if ver == "" {
		return false
	}
	for _, c := range ver {
		if c < '0' || c > '9' {
			return false
		}
	}
	n, err := strconv.Atoi(ver)
	if err != nil {
		return false
	}
	return n >= 300000
}
