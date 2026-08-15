// Capture a real Chrome WebAuthn assertion (virtual authenticator + PRF if available).
// bun poc/2fa-vault/web/e2e/capture.mjs
import { chromium } from "playwright";
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

const origin = "http://localhost:8787";
const challenge = crypto.getRandomValues(new Uint8Array(32));

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext();
const page = await context.newPage();
const cdp = await context.newCDPSession(page);
await cdp.send("WebAuthn.enable");
await cdp.send("WebAuthn.addVirtualAuthenticator", {
  options: {
    protocol: "ctap2",
    transport: "internal",
    hasResidentKey: true,
    hasUserVerification: true,
    isUserVerified: true,
    hasPrf: true,
  },
});

await page.route("**/*", (route) => {
  route.fulfill({
    contentType: "text/html",
    body: "<!doctype html><title>capture</title>",
  });
});
await page.goto(origin);

const fixture = await page.evaluate(async (chB64) => {
  const b64toBuf = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const bufToHex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
  const challenge = b64toBuf(chB64);
  const userId = crypto.getRandomValues(new Uint8Array(16));
  const created = await navigator.credentials.create({
    publicKey: {
      rp: { name: "2FA Vault", id: "localhost" },
      user: { id: userId, name: "vault", displayName: "vault" },
      challenge,
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
    },
  });
  const got = await navigator.credentials.get({
    publicKey: {
      challenge,
      rpId: "localhost",
      allowCredentials: [{ type: "public-key", id: created.rawId }],
      userVerification: "required",
    },
  });
  const spki = new Uint8Array(created.response.getPublicKey());
  const raw = spki.slice(spki.length - 65);
  const p256 = new Uint8Array(33);
  p256[0] = raw[64] & 1 ? 0x03 : 0x02;
  p256.set(raw.slice(1, 33), 1);
  return {
    credentialId: bufToHex(created.rawId),
    p256: bufToHex(p256),
    challenge: bufToHex(challenge),
    clientDataJSON: bufToHex(got.response.clientDataJSON),
    authenticatorData: bufToHex(got.response.authenticatorData),
    signature: bufToHex(got.response.signature),
  };
}, Buffer.from(challenge).toString("base64"));

const out = new URL("../../testdata/webauthn_get.json", import.meta.url);
mkdirSync(dirname(out.pathname), { recursive: true });
writeFileSync(out, JSON.stringify(fixture, null, 2));
console.log("wrote", out.pathname);
await browser.close();
