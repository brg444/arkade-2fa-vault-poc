// Capture a genuine Chrome WebAuthn assertion and prove PRF availability.
// This uses Bun plus Chrome's DevTools Protocol directly; Playwright is not
// required. PRF bytes never leave the page and are never written or logged.
//
//   bun poc/2fa-vault/web/e2e/capture.mjs

import { writeFileSync } from "node:fs";
import { addPRFAuthenticator, evaluate, launchChrome } from "./cdp.mjs";

const origin = "http://localhost:8787";
const challenge = crypto.getRandomValues(new Uint8Array(32));
const fixtureURL = new URL("../../testdata/webauthn_get.json", import.meta.url);

const server = Bun.serve({
  hostname: "127.0.0.1",
  port: 8787,
  fetch() {
    return new Response("<!doctype html><meta charset=utf-8><title>Arkade WebAuthn capture</title>", {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Security-Policy": "default-src 'none'; script-src 'none'; connect-src 'none'",
      },
    });
  },
});

let browser;
try {
  browser = await launchChrome(origin);
  await addPRFAuthenticator(browser.cdp);
  const captured = await evaluate(browser.cdp, browserCeremony, Buffer.from(challenge).toString("base64"));
  if (!captured || captured.prfLength !== 32 || !captured.fixture) {
    throw new Error("Chrome virtual authenticator did not return a 32-byte PRF result");
  }

  writeFileSync(fixtureURL, JSON.stringify(captured.fixture, null, 2) + "\n", { mode: 0o600 });
  console.log(`WebAuthn ES256 assertion captured; PRF ${captured.prfLength} bytes confirmed in-page`);
  console.log("wrote", fixtureURL.pathname);
} finally {
  server.stop(true);
  await browser?.close();
}

async function browserCeremony(challengeB64) {
  const fromB64 = (text) => Uint8Array.from(atob(text), (char) => char.charCodeAt(0));
  const toHex = (value) => [...new Uint8Array(value)]
    .map((byte) => byte.toString(16).padStart(2, "0")).join("");
  const challenge = fromB64(challengeB64);
  const prfSalt = new TextEncoder().encode("arkade-2fa-vault/prf/v1");
  const created = await navigator.credentials.create({
    publicKey: {
      rp: { name: "Arkade Vault", id: "localhost" },
      user: {
        id: crypto.getRandomValues(new Uint8Array(16)),
        name: "Arkade Vault",
        displayName: "Arkade Vault",
      },
      challenge,
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "required",
      },
      extensions: { prf: { eval: { first: prfSalt } } },
    },
  });
  if (!created || created.response.getPublicKeyAlgorithm() !== -7) {
    throw new Error("created credential is not ES256");
  }
  const got = await navigator.credentials.get({
    publicKey: {
      challenge,
      rpId: "localhost",
      allowCredentials: [{ type: "public-key", id: created.rawId }],
      userVerification: "required",
      extensions: { prf: { eval: { first: prfSalt } } },
    },
  });
  const prf = got?.getClientExtensionResults()?.prf?.results?.first;
  if (!(prf instanceof ArrayBuffer) || prf.byteLength !== 32) {
    throw new Error("PRF extension did not return exactly 32 bytes");
  }

  const spki = created.response.getPublicKey();
  const key = await crypto.subtle.importKey(
    "spki",
    spki,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"],
  );
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", key));
  if (raw.length !== 65 || raw[0] !== 0x04) throw new Error("unexpected P-256 public key encoding");
  const compressed = new Uint8Array(33);
  compressed[0] = (raw[64] & 1) === 1 ? 0x03 : 0x02;
  compressed.set(raw.subarray(1, 33), 1);

  // Return only public assertion evidence and the PRF length. The PRF result
  // itself stays in this page and becomes unreachable after evaluation.
  return {
    prfLength: prf.byteLength,
    fixture: {
      credentialId: toHex(created.rawId),
      p256: toHex(compressed),
      challenge: toHex(challenge),
      clientDataJSON: toHex(got.response.clientDataJSON),
      authenticatorData: toHex(got.response.authenticatorData),
      signature: toHex(got.response.signature),
    },
  };
}
