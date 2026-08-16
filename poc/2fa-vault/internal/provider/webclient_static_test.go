package provider

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestReviewerDirectP256BrowserBundleIsVendoredAndPinned(t *testing.T) {
	webDir := filepath.Join("..", "..", "web")
	app, err := os.ReadFile(filepath.Join(webDir, "app.js"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(app, []byte(`from "./directauth.js"`)) {
		t.Fatal("browser does not import the extracted direct-auth module")
	}
	if !bytes.Contains(app, []byte(`from "./enrollstore.js"`)) {
		t.Fatal("browser does not import the enrollment staging helper")
	}
	if !bytes.Contains(app, []byte("stagePending(localStorage, rec)")) {
		t.Fatal("browser must stage the encrypted record before POST /register")
	}
	if !bytes.Contains(app, []byte("promotePending(localStorage)")) {
		t.Fatal("browser must promote the pending record only after register success")
	}
	if !bytes.Contains(app, []byte("recoverEnrollment(enrollIO())")) {
		t.Fatal("browser must recover a pending enrollment on load")
	}
	if !bytes.Contains(app, []byte("assertArkadeChallenge(reviewed.parsed.arkadeChallenge, pre.challenge)")) {
		t.Fatal("browser ceremony must compare its independent Arkade digest to preflight")
	}
	recoveryStart := bytes.Index(app, []byte("async function recoverPendingEnrollment"))
	recoveryEnd := bytes.Index(app, []byte("function operationalFrom"))
	if recoveryStart < 0 || recoveryEnd <= recoveryStart {
		t.Fatal("browser pending-enrollment recovery function missing")
	}
	recovery := app[recoveryStart:recoveryEnd]
	getAt := bytes.Index(recovery, []byte("navigator.credentials.get"))
	decryptAt := bytes.Index(recovery, []byte("crypto.subtle.decrypt"))
	verifyRoutineAt := bytes.Index(recovery, []byte("assertPhoneRoutineBIP340Pub(phoneRoutineBip340Pub"))
	registerAt := bytes.Index(recovery, []byte("enrollIO().register"))
	promoteAt := bytes.Index(recovery, []byte("promotePending(localStorage)"))
	if getAt < 0 || decryptAt <= getAt || verifyRoutineAt <= decryptAt || registerAt <= verifyRoutineAt || promoteAt <= registerAt ||
		!bytes.Contains(recovery, []byte(`userVerification: "required"`)) ||
		!bytes.Contains(recovery, []byte("extensions: { prf:")) {
		t.Fatal("pending recovery must perform UV+PRF, decrypt and verify locally before exact registration and promotion")
	}
	enrollStart := bytes.Index(app, []byte("async function enroll()"))
	if enrollStart < 0 {
		t.Fatal("browser enrollment function missing")
	}
	enroll := app[enrollStart:recoveryStart]
	pendingAt := bytes.Index(enroll, []byte(`recovery.action === "pending-requires-user-presence"`))
	createAt := bytes.Index(enroll, []byte("navigator.credentials.create"))
	stageAt := bytes.Index(enroll, []byte("stagePending(localStorage, rec)"))
	if pendingAt < 0 || createAt <= pendingAt || stageAt <= createAt {
		t.Fatal("pending recovery must run before creating or staging a replacement credential")
	}
	if bytes.Count(app, []byte("X-Vault-Enrollment-Token")) != 1 || !bytes.Contains(app, []byte(`"/v1/register"`)) {
		t.Fatal("browser must send the bootstrap token only through the registration helper")
	}
	if !bytes.Contains(app, []byte("requireFrozenReview")) {
		t.Fatal("browser must freeze the reviewed intent")
	}
	if !bytes.Contains(app, []byte("validateAuthorizedPSBT")) {
		t.Fatal("browser must check the authorized PSBT provider-signature delta")
	}
	if !bytes.Contains(app, []byte(`"/v1/publish"`)) {
		t.Fatal("browser must publish by challenge, not by submitting a PSBT")
	}
	if !bytes.Contains(app, []byte(`"/v1/demo/mine"`)) {
		t.Fatal("demo golden path must mine once after a zero-confirmation publish")
	}
	if !bytes.Contains(app, []byte(`"/v1/tx?challenge="`)) {
		t.Fatal("demo golden path must confirm by challenge, not by a client-chosen txid")
	}
	if !bytes.Contains(app, []byte("Number(funded.confirmations) < 1")) {
		t.Fatal("demo fund must require a confirmed prevout before accepting it")
	}
	if bytes.Contains(app, []byte(`"/v1/demo/submit"`)) {
		t.Fatal("browser must not post a client PSBT to demo submit")
	}
	if bytes.Contains(app, []byte(`"/v1/demo/owner-draft"`)) || bytes.Contains(app, []byte(`"/v1/demo/owner-complete"`)) {
		t.Fatal("browser must not call owner-draft or owner-complete")
	}
	if bytes.Contains(app, []byte(`from "./vendor/p256.js"`)) {
		t.Fatal("app.js must not import p256.js directly; derivation belongs in directauth.js")
	}
	directAuth, err := os.ReadFile(filepath.Join(webDir, "directauth.js"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(directAuth, []byte(`from "./vendor/p256.js"`)) {
		t.Fatal("directauth.js does not import the same-origin P-256 bundle")
	}
	if !bytes.Contains(directAuth, []byte("arkade-2fa-vault/direct-p256/v1")) {
		t.Fatal("directauth.js does not use the canonical HKDF info prefix")
	}
	if !bytes.Contains(directAuth, []byte("prf must be exactly 32 bytes")) {
		t.Fatal("directauth.js must require a 32-byte PRF")
	}
	if bytes.Contains(app, []byte("p256: bytesToHex")) || bytes.Contains(app, []byte("rec.p256")) {
		t.Fatal("browser must persist webauthnP256, not rec.p256")
	}
	if !bytes.Contains(app, []byte("webauthnP256:")) {
		t.Fatal("browser must persist the WebAuthn pub as webauthnP256")
	}
	if !bytes.Contains(directAuth, []byte("isValidPrivateKey")) {
		t.Fatal("directauth.js must rejection-sample with p256.utils.isValidPrivateKey")
	}
	if !bytes.Contains(directAuth, []byte("toCompactRawBytes()")) ||
		bytes.Contains(directAuth, []byte("toCompactRawBytes ?")) {
		t.Fatal("directauth.js must require p256.sign(...).toCompactRawBytes() without an object fallback")
	}
	if !bytes.Contains(directAuth, []byte("prehash: false, lowS: true")) {
		t.Fatal("directauth.js verify must pass {prehash:false, lowS:true}")
	}

	vendorDir := filepath.Join(webDir, "vendor")
	artifact, err := os.ReadFile(filepath.Join(vendorDir, "p256.js"))
	if err != nil {
		t.Fatalf("vendored P-256 bundle: %v", err)
	}
	if len(artifact) == 0 {
		t.Fatal("vendored P-256 bundle is empty")
	}

	rebuild, err := os.ReadFile(filepath.Join(vendorDir, "rebuild.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(rebuild, []byte(`export { p256 } from "@noble/curves/p256.js"`)) ||
		!bytes.Contains(rebuild, []byte(`bun build ./p256.entry.js --outfile "$OUT/p256.js"`)) ||
		!bytes.Contains(rebuild, []byte(`"$OUT/p256.js"`)) {
		t.Fatal("vendor rebuild recipe does not export, bun-build, and hash p256.js")
	}

	notice, err := os.ReadFile(filepath.Join(vendorDir, "NOTICE.md"))
	if err != nil {
		t.Fatal(err)
	}
	pinned := regexp.MustCompile("`p256\\.js` \\| `([0-9a-f]{64})`").FindSubmatch(notice)
	if len(pinned) != 2 {
		t.Fatal("NOTICE.md does not pin the p256.js artifact SHA-256")
	}
	sum := sha256.Sum256(artifact)
	if got, want := hex.EncodeToString(sum[:]), string(pinned[1]); got != want {
		t.Fatalf("p256.js SHA-256 = %s, NOTICE.md pins %s", got, want)
	}
}

// TestWebClientHasNoRemoteImportsAndSetsCSP checks that the shipped page does
// not load signing code from a remote origin. It does not prove that a
// compromised provider cannot replace these first-party files.
func TestWebClientHasNoRemoteImportsAndSetsCSP(t *testing.T) {
	webDir := filepath.Join("..", "..", "web")
	remoteImport := regexp.MustCompile(`(?i)((import\s*\()|(import\s+[^;]*from\s+)|(src\s*=\s*))['"]https?://`)
	anyURL := regexp.MustCompile(`(?i)https?://`)

	for _, name := range []string{"app.js", "directauth.js", "enrollstore.js", "index.html"} {
		raw, err := os.ReadFile(filepath.Join(webDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if remoteImport.Match(raw) {
			t.Fatalf("%s imports a remote http(s) URL", name)
		}
		if anyURL.Match(raw) {
			t.Fatalf("%s contains an http(s) URL; signing code must stay same-origin", name)
		}
	}

	html, err := os.ReadFile(filepath.Join(webDir, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(html, []byte(`http-equiv="Content-Security-Policy"`)) {
		t.Fatal("index.html missing Content-Security-Policy")
	}
	if !bytes.Contains(html, []byte("script-src 'self'")) {
		t.Fatal("index.html CSP does not lock script-src to self")
	}
	if !bytes.Contains(html, []byte("connect-src 'self'")) {
		t.Fatal("index.html CSP does not lock connect-src to self")
	}

	handler := Handler(nil, webDir)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("index.html status %d", rec.Code)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || !strings.Contains(csp, "connect-src 'self'") {
		t.Fatalf("response CSP missing same-origin script/connect locks: %q", csp)
	}
	if strings.Contains(csp, "http:") || strings.Contains(csp, "https:") || strings.Contains(csp, "*") {
		t.Fatalf("response CSP allows a remote source: %q", csp)
	}
}
