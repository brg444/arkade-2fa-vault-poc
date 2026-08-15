// Opt-in real-stack acceptance driver. It never starts a Provider or accepts
// the unsafe local signer: /v1/demo/info must prove the running stack enabled
// its RemoteSigner-only regtest controller.
//
//   VAULT_E2E_RESULT_FILE=/tmp/result.json bun \
//     poc/2fa-vault/web/e2e/live-app.mjs

import { writeFileSync } from "node:fs";
import { addPRFAuthenticator, evaluate, launchChrome } from "./cdp.mjs";
import { auditLiveRequests, validateLiveState } from "./live-contract.mjs";

const origin = "http://localhost:8787";

const initialDemo = await getJSON("/v1/demo/info");
if (initialDemo.demo !== true || initialDemo.network !== "regtest" || initialDemo.signerMode !== "remote" || Number(initialDemo.remoteSignerSuccesses) !== 0) {
  throw new Error(`live acceptance requires RemoteSigner-only regtest demo mode: ${JSON.stringify(initialDemo)}`);
}
const initialStatus = await getJSON("/v1/status");
if (initialStatus.enrolled) {
  throw new Error("live acceptance requires a fresh, unenrolled provider volume");
}

let browser;
let terminating = false;
async function terminate(code) {
  if (terminating) return;
  terminating = true;
  try { await browser?.close(); } finally { process.exit(code); }
}
process.on("SIGTERM", () => { void terminate(143); });
process.on("SIGINT", () => { void terminate(130); });
try {
  browser = await launchChrome(origin);
  await withTimeout(addPRFAuthenticator(browser.cdp), 15_000, "virtual authenticator setup");
  await withTimeout(browser.cdp.send("Network.enable"), 15_000, "CDP network setup");

  const requests = [];
  browser.cdp.on("Network.requestWillBeSent", ({ request }) => {
    if (request.method !== "POST" || !request.postData) return;
    const path = new URL(request.url).pathname;
    if (path.startsWith("/v1/")) {
      requests.push({ path, body: JSON.parse(request.postData) });
    }
  });

  const browserResult = await withTimeout(evaluate(browser.cdp, runLiveFlow), 300_000, "browser golden path");
  auditLiveRequests(requests, browserResult.challenge);

  const tx = await getJSON(`/v1/tx?challenge=${browserResult.challenge}`);
  const status = await getJSON("/v1/status");
  const finalDemo = await getJSON("/v1/demo/info");
  const result = validateLiveState({ browserResult, tx, status, finalDemo });
  if (process.env.VAULT_E2E_RESULT_FILE) {
    writeFileSync(process.env.VAULT_E2E_RESULT_FILE, JSON.stringify(result), { mode: 0o600 });
  }
  console.log(`ARKADE_LIVE_RESULT=${JSON.stringify(result)}`);
} finally {
  if (!terminating) await browser?.close();
}

async function getJSON(path) {
  const response = await fetch(origin + path, {
    headers: { Accept: "application/json" },
    signal: AbortSignal.timeout(15_000),
  });
  const text = await response.text();
  let value;
  try { value = JSON.parse(text); } catch { throw new Error(`${path}: ${text}`); }
  if (!response.ok) throw new Error(`${path}: ${value.error || text}`);
  return value;
}

async function withTimeout(promise, milliseconds, label) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out`)), milliseconds);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function runLiveFlow() {
  const wait = async (predicate, label, timeout = 120_000) => {
    const start = Date.now();
    while (Date.now() - start < timeout) {
      if (await predicate()) return;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    const out = document.getElementById("out")?.textContent || "";
    const status = document.getElementById("status")?.textContent || "";
    throw new Error(`${label} timed out; out=${out}; status=${status}`);
  };
  const byID = (id) => {
    const element = document.getElementById(id);
    if (!element) throw new Error(`missing #${id}`);
    return element;
  };
  const parsedOut = () => {
    try { return JSON.parse(byID("out").textContent); } catch { return null; }
  };

  await wait(
    () => typeof byID("btn-enroll").onclick === "function" && !byID("btn-enroll").disabled,
    "app bootstrap",
  );
  if (byID("demo-controls").hidden) throw new Error("regtest demo controls are not enabled");

  byID("btn-enroll").click();
  await wait(() => {
    if (localStorage.getItem("vault-hot-v1") && !byID("btn-enroll").disabled) return true;
    if (!byID("btn-enroll").disabled && byID("out").textContent !== "") {
      throw new Error(`passkey enrollment failed: ${byID("out").textContent}`);
    }
    return false;
  }, "passkey enrollment");

  byID("btn-fund").click();
  await wait(() => {
    const funded = parsedOut();
    if (funded?.prevTxHex && Number(funded.confirmations) >= 1 && !byID("btn-fund").disabled) return true;
    if (!byID("btn-fund").disabled && byID("out").textContent !== "") {
      throw new Error(`Operational funding failed: ${byID("out").textContent}`);
    }
    return false;
  }, "confirmed Operational funding");

  byID("btn-review").click();
  await wait(() => {
    if (!byID("view-review").hidden && !byID("btn-review").disabled) return true;
    if (!byID("btn-review").disabled && byID("view-review").hidden) {
      throw new Error(`review failed: ${byID("out").textContent}`);
    }
    return false;
  }, "reviewed spend");

  byID("btn-sign").click();
  await wait(() => {
    const receipt = parsedOut();
    if (receipt?.authorized && receipt?.published && !byID("btn-sign").disabled) return true;
    if (!byID("btn-sign").disabled && byID("out").textContent !== "") {
      throw new Error(`authorization or publication failed: ${byID("out").textContent}`);
    }
    return false;
  }, "RemoteSigner authorization and confirmation");

  const receipt = parsedOut();
  if (receipt.authorized.replay !== false) throw new Error("fresh authorization replay flag");
  if (!/^[0-9a-f]{64}$/.test(receipt.challenge || "")) throw new Error("invalid Arkade challenge");
  if (!/^[0-9a-f]{64}$/.test(receipt.published.txid || "")) throw new Error("invalid published txid");
  if (!/^[0-9a-f]{64}$/.test(receipt.expectedTxid || "") || receipt.published.txid !== receipt.expectedTxid) {
    throw new Error("published txid does not match the browser-authorized PSBT");
  }
  if (Number(receipt.published.confirmations) < 1) throw new Error("published transaction is not confirmed");
  return {
    challenge: receipt.challenge,
    txid: receipt.published.txid,
    expectedTxid: receipt.expectedTxid,
    confirmations: Number(receipt.published.confirmations),
    replay: receipt.authorized.replay,
  };
}
