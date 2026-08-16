// Genuine headless-Chrome PRF ceremony through the real browser app and
// Provider HTTP API. This intentionally uses -unsafe-local-signer so it can
// run without Docker, Emulator or bitcoind; it does not prove RemoteSigner.
//
//   bun poc/2fa-vault/web/e2e/full-app.mjs

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { addPRFAuthenticator, evaluate, launchChrome } from "./cdp.mjs";

const origin = "http://localhost:8787";
const repoRoot = fileURLToPath(new URL("../../../../", import.meta.url));
const temp = mkdtempSync(join(tmpdir(), "arkade-vault-app-e2e-"));
const providerBin = join(temp, "vault-provider");
const dbPath = join(temp, "vault.sqlite");
const webDir = join(repoRoot, "poc/2fa-vault/web");
const go = process.env.GO_BIN || "go";
const recoveryKeyPub = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const externalOwnerWalletPub = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const vaultCosignerPriv = "00".repeat(31) + "03";
const arkadeCosignerPriv = "00".repeat(31) + "04";

let provider;
let providerExited = false;
let browser;
try {
  await checkedSpawn([go, "build", "-o", providerBin, "./poc/2fa-vault/cmd/provider"], {
    cwd: repoRoot,
    env: { ...process.env, GOTOOLCHAIN: process.env.GOTOOLCHAIN || "local" },
  });
  provider = Bun.spawn([
    providerBin,
    "-addr", "127.0.0.1:8787",
    "-db", dbPath,
    "-web", webDir,
    "-external-owner-wallet", externalOwnerWalletPub,
    "-recovery-key", recoveryKeyPub,
    "-unsafe-local-signer",
    "-vault-cosigner-key", vaultCosignerPriv,
    "-arkade-key", arkadeCosignerPriv,
    "-demo=false",
    "-bitcoin-rpc", "",
  ], {
    cwd: repoRoot,
    stdout: "inherit",
    stderr: "inherit",
    env: { ...process.env, VAULT_DEMO: "", VAULT_BITCOIN_RPC: "" },
  });
  provider.exited.then(() => { providerExited = true; });

  await waitForHealth(() => providerExited);
  browser = await launchChrome(origin);
  await addPRFAuthenticator(browser.cdp);
  await browser.cdp.send("Network.enable");

  const requests = [];
  browser.cdp.on("Network.requestWillBeSent", ({ request }) => {
    if (request.method !== "POST" || !request.postData) return;
    const path = new URL(request.url).pathname;
    if (["/v1/register", "/v1/bind", "/v1/authorize"].includes(path)) {
      requests.push({ path, body: JSON.parse(request.postData) });
    }
  });

  const result = await evaluate(browser.cdp, runAppFlow);
  auditRequestShapes(requests);
  if (!result?.enrolled || result.periodSpent !== 20_500 || result.replay !== false || result.publisherConfigured !== false) {
    throw new Error(`unexpected app result: ${JSON.stringify(result)}`);
  }
  console.log("full browser app ceremony passed", JSON.stringify(result));
  console.log("verified exact register/bind/authorize request shapes; no PRF or private-key field crossed the API");
} finally {
  try {
    await browser?.close();
  } finally {
    if (provider) {
      provider.kill();
      await Promise.race([provider.exited, Bun.sleep(2_000)]);
    }
    rmSync(temp, { recursive: true, force: true });
  }
}

async function checkedSpawn(command, options) {
  const child = Bun.spawn(command, { ...options, stdout: "inherit", stderr: "inherit" });
  const code = await child.exited;
  if (code !== 0) throw new Error(`${command[0]} exited with status ${code}`);
}

async function waitForHealth(exited) {
  for (let i = 0; i < 300; i++) {
    if (exited()) throw new Error("Provider exited before becoming healthy");
    try {
      const response = await fetch(`${origin}/health`);
      if (response.ok) return;
    } catch {
      // The listener is still starting.
    }
    await Bun.sleep(50);
  }
  throw new Error("timed out waiting for Provider health");
}

function auditRequestShapes(requests) {
  const expected = new Map([
    ["/v1/register", ["credentialId", "phoneDirectP256", "phoneRoutineBip340Pub", "webauthnP256"]],
    ["/v1/bind", ["authenticatorData", "clientDataJSON", "credentialId", "directSig", "psbt", "signature"]],
    ["/v1/authorize", ["authenticatorData", "clientDataJSON", "credentialId", "psbt", "signature"]],
  ]);
  for (const [path, keys] of expected) {
    const matches = requests.filter((request) => request.path === path);
    if (matches.length !== 1) throw new Error(`${path} request count = ${matches.length}, want 1`);
    const got = Object.keys(matches[0].body).sort();
    if (JSON.stringify(got) !== JSON.stringify(keys)) {
      throw new Error(`${path} fields = ${JSON.stringify(got)}, want ${JSON.stringify(keys)}`);
    }
  }
  const forbidden = new Set(["prf", "scalar", "privatekey", "privatekeyhex", "hotprivate", "kek", "ciphertext", "nonce"]);
  const walk = (value) => {
    if (!value || typeof value !== "object") return;
    for (const [key, child] of Object.entries(value)) {
      if (forbidden.has(key.toLowerCase())) throw new Error(`forbidden API field: ${key}`);
      walk(child);
    }
  };
  for (const request of requests) walk(request.body);
}

async function runAppFlow() {
  const wait = async (predicate, label, timeout = 30_000) => {
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
  const little = (value, bytes) => {
    let n = BigInt(value);
    let hex = "";
    for (let i = 0; i < bytes; i++) {
      hex += Number(n & 0xffn).toString(16).padStart(2, "0");
      n >>= 8n;
    }
    return hex;
  };

  await wait(() => typeof byID("btn-enroll").onclick === "function" && !byID("btn-enroll").disabled, "app bootstrap");
  byID("btn-enroll").click();
  await wait(() => localStorage.getItem("arkade-vault-enrollment-v3") && !byID("btn-enroll").disabled, "passkey enrollment");

  const status = await fetch("/v1/status").then((response) => response.json());
  if (!status.enrolled || !/^[0-9a-f]{68}$/.test(status.operationalScript || "")) {
    throw new Error("enrollment did not return a canonical P2TR Operational script");
  }
  const fundingValue = 100_000;
  const scriptBytes = status.operationalScript.length / 2;
  const prevTxHex = [
    "02000000",
    "01",
    "11".repeat(32),
    "00000000",
    "00",
    "ffffffff",
    "01",
    little(fundingValue, 8),
    scriptBytes.toString(16).padStart(2, "0"),
    status.operationalScript,
    "00000000",
  ].join("");

  byID("prevtx").value = prevTxHex;
  byID("vout").value = "0";
  byID("dest").value = "0014" + "22".repeat(20);
  byID("amount").value = "20000";
  byID("fee").value = "500";
  byID("btn-review").click();
  await wait(() => {
    if (!byID("btn-review").disabled && byID("view-review").hidden) {
      throw new Error(`review failed: ${byID("out").textContent}`);
    }
    return !byID("view-review").hidden && !byID("btn-review").disabled;
  }, "reviewed draft");

  byID("btn-sign").click();
  await wait(() => {
    if (!byID("btn-sign").disabled && !byID("out").textContent.includes('"authorized"')) {
      throw new Error(`authorization failed: ${byID("out").textContent}`);
    }
    return byID("out").textContent.includes('"authorized"') && !byID("btn-sign").disabled;
  }, "authorized spend");
  const receipt = JSON.parse(byID("out").textContent);
  const finalStatus = await fetch("/v1/status").then((response) => response.json());
  return {
    enrolled: finalStatus.enrolled,
    periodSpent: Number(finalStatus.periodSpent),
    replay: receipt.authorized?.replay,
    publisherConfigured: receipt.published !== null,
    operationalAddress: finalStatus.operationalAddress,
  };
}
