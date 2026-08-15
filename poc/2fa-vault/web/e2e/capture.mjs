// Capture a genuine Chrome WebAuthn assertion and prove PRF availability.
// This uses Bun plus Chrome's DevTools Protocol directly; Playwright is not
// required. PRF bytes never leave the page and are never written or logged.
//
//   bun poc/2fa-vault/web/e2e/capture.mjs

import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

const origin = "http://localhost:8787";
const profile = mkdtempSync(join(tmpdir(), "arkade-webauthn-"));
const chrome = findChrome();
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

const child = Bun.spawn([
  chrome,
  "--headless=new",
  "--disable-gpu",
  "--disable-dev-shm-usage",
  "--no-first-run",
  "--no-default-browser-check",
  "--remote-debugging-port=0",
  "--remote-allow-origins=*",
  `--user-data-dir=${profile}`,
  origin,
], { stdout: "pipe", stderr: "pipe" });

let cdp;
try {
  const port = await devtoolsPort(profile, child);
  const page = await pageTarget(port, origin, child);
  cdp = await CDP.connect(page.webSocketDebuggerUrl);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      ctap2Version: "ctap2_1",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
      hasPrf: true,
    },
  });

  const evaluated = await cdp.send("Runtime.evaluate", {
    expression: `(${browserCeremony.toString()})(${JSON.stringify(toB64(challenge))})`,
    awaitPromise: true,
    returnByValue: true,
  });
  if (evaluated.exceptionDetails) {
    throw new Error(evaluated.exceptionDetails.exception?.description || evaluated.exceptionDetails.text);
  }
  const captured = evaluated.result?.value;
  if (!captured || captured.prfLength !== 32 || !captured.fixture) {
    throw new Error("Chrome virtual authenticator did not return a 32-byte PRF result");
  }

  writeFileSync(fixtureURL, JSON.stringify(captured.fixture, null, 2) + "\n", { mode: 0o600 });
  console.log(`WebAuthn ES256 assertion captured; PRF ${captured.prfLength} bytes confirmed in-page`);
  console.log("wrote", fixtureURL.pathname);
} finally {
  cdp?.close();
  server.stop(true);
  child.kill();
  await Promise.race([child.exited, Bun.sleep(2_000)]);
  rmSync(profile, { recursive: true, force: true });
}

function findChrome() {
  const candidates = [
    process.env.CHROME_BIN,
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
  ].filter(Boolean);
  const found = candidates.find(existsSync);
  if (!found) throw new Error("Chrome not found; set CHROME_BIN to a Chrome/Chromium executable");
  return found;
}

async function devtoolsPort(dir, process) {
  const active = join(dir, "DevToolsActivePort");
  for (let i = 0; i < 200; i++) {
    if (existsSync(active)) {
      const port = Number(readFileSync(active, "utf8").split(/\r?\n/, 1)[0]);
      if (Number.isInteger(port) && port > 0) return port;
    }
    if (await exited(process)) throw new Error("Chrome exited before opening DevTools");
    await Bun.sleep(50);
  }
  throw new Error("timed out waiting for Chrome DevTools");
}

async function pageTarget(port, url, process) {
  for (let i = 0; i < 200; i++) {
    if (await exited(process)) throw new Error("Chrome exited before creating a page target");
    try {
      const response = await fetch(`http://127.0.0.1:${port}/json/list`);
      const targets = await response.json();
      const target = targets.find((item) => item.type === "page" && item.url.startsWith(url));
      if (target?.webSocketDebuggerUrl) return target;
    } catch {
      // Chrome can publish the port before the target list is ready.
    }
    await Bun.sleep(50);
  }
  throw new Error("timed out waiting for the localhost page target");
}

async function exited(process) {
  return (await Promise.race([process.exited.then(() => true), Bun.sleep(0).then(() => false)]));
}

function toB64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

class CDP {
  static async connect(url) {
    const ws = new WebSocket(url);
    await new Promise((resolve, reject) => {
      ws.addEventListener("open", resolve, { once: true });
      ws.addEventListener("error", () => reject(new Error("DevTools WebSocket failed")), { once: true });
    });
    return new CDP(ws);
  }

  constructor(ws) {
    this.ws = ws;
    this.nextID = 1;
    this.pending = new Map();
    ws.addEventListener("message", (event) => {
      const message = JSON.parse(String(event.data));
      if (!message.id) return;
      const pending = this.pending.get(message.id);
      if (!pending) return;
      this.pending.delete(message.id);
      if (message.error) pending.reject(new Error(`${message.error.message} (${message.error.code})`));
      else pending.resolve(message.result);
    });
    ws.addEventListener("close", () => {
      for (const pending of this.pending.values()) pending.reject(new Error("DevTools WebSocket closed"));
      this.pending.clear();
    });
  }

  send(method, params = {}) {
    const id = this.nextID++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }

  close() {
    this.ws.close();
  }
}

async function browserCeremony(challengeB64) {
  const fromB64 = (text) => Uint8Array.from(atob(text), (char) => char.charCodeAt(0));
  const toHex = (value) => [...new Uint8Array(value)]
    .map((byte) => byte.toString(16).padStart(2, "0")).join("");
  const challenge = fromB64(challengeB64);
  const prfSalt = new TextEncoder().encode("arkade-2fa-vault/prf/v1");
  const created = await navigator.credentials.create({
    publicKey: {
      rp: { name: "2FA Vault", id: "localhost" },
      user: {
        id: crypto.getRandomValues(new Uint8Array(16)),
        name: "vault",
        displayName: "vault",
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
