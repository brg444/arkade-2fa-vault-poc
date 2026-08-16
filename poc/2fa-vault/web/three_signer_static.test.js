import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";

function source(name) {
  return readFileSync(new URL(`./${name}`, import.meta.url), "utf8");
}

test("browser ceremony reconciles the complete v3 descriptor identity", () => {
  const app = source("app.js");
  expect(app).toContain("assertDescriptorIdentity");
  expect(app).toContain("Object.assign(rec, reconcileSignerIdentity(null, st))");
  expect(app.match(/reconcileSignerIdentity\(rec, live\)/g)?.length).toBeGreaterThanOrEqual(2);
  expect(app).toContain("tweakedVaultCosignerXOnly: rec.tweakedVaultCosignerXOnly");
  expect(app).toContain("tweakedArkadeCosignerXOnly: rec.tweakedArkadeCosignerXOnly");
  expect(app).not.toMatch(/externalOwner(?:Wallet)?(?:Priv|Secret)|externalOwnerSignPSBT/i);
});

test("local v3 enrollment record binds every public role and policy identity", () => {
  const store = source("enrollstore.js");
  for (const field of [
    "externalOwnerWalletPub",
    "recoveryKeyPub",
    "vaultCosignerBasePub",
    "tweakedVaultCosignerXOnly",
    "arkadeCosignerBasePub",
    "tweakedArkadeCosignerXOnly",
    "arkadeCosignerOrigin",
    "arkadeCosignerVersion",
    "network",
    "templateVersion",
    "policyVersion",
  ]) {
    expect(store).toContain(`"${field}"`);
  }
  expect(store).toContain('STORE = "arkade-vault-enrollment-v3"');
  expect(store).not.toContain('STORE = "arkade-vault-enrollment-v2"');
  expect(store).toContain("persisted descriptor");
  expect(store).toContain("does not match vault status");
});

test("authorized response is constrained to PhoneRoutine plus the exact two cosigner additions", () => {
  const verifier = source("psbtcheck.js");
  expect(verifier).toContain("after.length !== 3");
  expect(verifier).toContain("extras.length !== 2");
  expect(verifier).toContain("new Set([phoneRoutine.pub, wantVaultCosigner, wantArkade]).size !== 3");
  expect(verifier).toContain("expected.delete(extra.pub)");
  expect(verifier).toContain("duplicate or substituted routine cosigner");
  expect(verifier).toContain("routine spend requires recipient, recursive change, and packet outputs");
});

test("ceremony retries the staged authorize body before generating fresh signatures", () => {
  const app = source("app.js");
  const ceremony = app.slice(
    app.indexOf("async function ceremony()"),
    app.indexOf("async function resumeAuthorization"),
  );
  const retryAt = ceremony.indexOf("resumeAuthorization(rec, reviewKey)");
  expect(retryAt).toBeGreaterThan(0);
  expect(ceremony.indexOf('api("/v1/preflight"')).toBeGreaterThan(retryAt);
  expect(ceremony.indexOf("navigator.credentials.get")).toBeGreaterThan(retryAt);
  expect(ceremony.indexOf("signDirectP256")).toBeGreaterThan(retryAt);
  expect(ceremony.indexOf("phoneRoutineSignPSBT")).toBeGreaterThan(retryAt);
  expect(ceremony.indexOf("authorizeRetry.stage(")).toBeGreaterThan(retryAt);

  expect(app).toContain('apiEncoded("/v1/authorize", pending.bodyJSON)');
  expect(app).toContain("invalidateReviewedIntent");
  expect(app).toContain('addEventListener("input", invalidateReviewedIntent)');
});

test("authorize retry material is page-memory-only and cleared on completion", () => {
  const retry = source("authorizeretry.js");
  expect(retry).not.toMatch(/localStorage|sessionStorage|indexedDB|document\.cookie/);
  const authorizedAt = retry.indexOf("markAuthorized(reviewKey, receipt)");
  const clearAt = retry.indexOf("pending = null", authorizedAt);
  expect(authorizedAt).toBeGreaterThan(0);
  expect(clearAt).toBeGreaterThan(authorizedAt);
});
