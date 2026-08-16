import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";

function source(name) {
  return readFileSync(new URL(`./${name}`, import.meta.url), "utf8");
}

test("browser ceremony reconciles and verifies both collaborative signer identities", () => {
  const app = source("app.js");
  expect(app).toContain("assertArkadeEmulatorIdentity");
  expect(app).toContain("Object.assign(rec, reconcileSignerIdentity(null, st))");
  expect(app.match(/reconcileSignerIdentity\(rec, live\)/g)?.length).toBeGreaterThanOrEqual(2);
  expect(app).toContain("tweakedProviderXOnly: rec.tweakedProviderXOnly");
  expect(app).toContain("tweakedArkadeXOnly: rec.tweakedArkadeXOnly");
});

test("local enrollment record binds the full public Arkade emulator identity", () => {
  const store = source("enrollstore.js");
  for (const field of [
    "arkadeEmulatorBasePub",
    "tweakedArkadeXOnly",
    "arkadeEmulatorOrigin",
    "arkadeEmulatorVersion",
    "network",
  ]) {
    expect(store).toContain(`"${field}"`);
  }
  expect(store).toContain("persisted Arkade emulator");
  expect(store).toContain("does not match vault status");
});

test("authorized response is constrained to the exact three-signature set", () => {
  const verifier = source("psbtcheck.js");
  expect(verifier).toContain("after.length !== 3");
  expect(verifier).toContain("extras.length !== 2");
  expect(verifier).toContain("new Set([hot.pub, wantProvider, wantArkade]).size !== 3");
  expect(verifier).toContain("expected.delete(extra.pub)");
  expect(verifier).toContain("duplicate or substituted collaborative signer");
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
  expect(ceremony.indexOf("hotSignPSBT")).toBeGreaterThan(retryAt);
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
