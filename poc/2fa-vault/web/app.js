import { secp256k1 } from "./vendor/secp256k1.js";
import {
  deriveDirectP256,
  signDirectP256,
  zeroBytes,
} from "./directauth.js";
import {
  assertDirectP256,
  assertHotPub,
  bytesToHex,
  hexToBytes,
  hotSignPSBT,
  reviewFields,
  validateAuthorizedPSBT,
  validateBoundPSBT,
  validateDraftPSBT,
} from "./psbtcheck.js";
import {
  loadMain,
  recoverEnrollment,
  stagePending,
  promotePending,
  assertTweakedProvider,
} from "./enrollstore.js";
import { compressedES256PublicKey } from "./webauthnkey.js";

const PRF_SALT = new TextEncoder().encode("arkade-2fa-vault/prf/v1");
const HKDF_INFO = new TextEncoder().encode("arkade-2fa-vault/kek/v1");

const $ = (id) => document.getElementById(id);

let reviewed = null;
let busy = false;

const BUSY_CONTROLS = [
  "btn-enroll", "btn-fund", "btn-review", "btn-sign",
  "btn-reject-cap", "btn-reject-intent",
  "dest", "amount", "fee", "prevtx", "vout",
];

function setBusy(next) {
  busy = next;
  for (const id of BUSY_CONTROLS) if ($(id)) $(id).disabled = next;
}

async function runExclusive(fn) {
  if (busy) throw new Error("another vault operation is in progress");
  setBusy(true);
  try { return await fn(); } finally { setBusy(false); }
}

async function api(path, body) {
  const res = await fetch(path, {
    method: body ? "POST" : "GET",
    headers: body
      ? { "Content-Type": "application/json", Accept: "application/json" }
      : { Accept: "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { throw new Error(text); }
  if (!res.ok) throw new Error(data.error || text);
  return data;
}

function loadRec() {
  return loadMain(localStorage);
}

function enrollIO() {
  return {
    storage: localStorage,
    register: (body) => api("/v1/register", body),
    status: () => api("/v1/status"),
  };
}

function readIntent() {
  return {
    prevTxHex: $("prevtx").value.trim(),
    vout: Number($("vout").value),
    recipientScript: $("dest").value.trim(),
    recipientAmount: Number($("amount").value),
    fee: Number($("fee").value),
  };
}

function intentKey(intent) {
  return JSON.stringify(intent);
}

async function refresh() {
  const st = await api("/v1/status");
  const demo = await demoInfo();
  st.savingsExcludesProvider = !!st.savingsExcludesProvider;
  $("status").textContent = JSON.stringify({
    ...st,
    savingsExcludesProvider: st.savingsExcludesProvider,
    preflightChallengeTrust: "browser signs the provider preflight challenge; it does not independently recompute the Arkade sighash",
  }, null, 2);
  if ($("savings-note")) {
    $("savings-note").textContent = st.savingsAddress
      ? (st.savingsExcludesProvider
        ? "Savings excludes the provider key (no collaborative path)."
        : "Savings provider exclusion check failed.")
      : "";
  }
  toggleDemo(demo);
  const rec = loadRec();
  if (rec?.hotPub && st.hotPub) assertHotPub(rec.hotPub, rec.hotPub, st.hotPub);
  if (rec?.directP256) assertDirectP256(rec.directP256, rec.directP256, st.directP256);
  if (rec?.tweakedProviderXOnly) {
    assertTweakedProvider(rec.tweakedProviderXOnly, st.tweakedProviderXOnly);
  }
  return st;
}

async function demoInfo() {
  try {
    return await api("/v1/demo/info");
  } catch {
    return null;
  }
}

function toggleDemo(demo) {
  const on = !!(demo && demo.demo);
  for (const id of ["demo-controls", "fund-row"]) {
    if ($(id)) $(id).hidden = !on;
  }
  for (const id of ["prevtx-row", "vout-row"]) {
    if ($(id)) $(id).hidden = on;
  }
}

async function deriveKEK(prf) {
  const key = await crypto.subtle.importKey("raw", prf, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: HKDF_INFO },
    key,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function prfFrom(cred) {
  const ext = cred.getClientExtensionResults();
  return ext?.prf?.results?.first || null;
}

function showParsed(parsed) {
  $("review").textContent = JSON.stringify(reviewFields(parsed), null, 2);
}

async function enroll() {
  let prf;
  let scalar;
  let hot;
  try {
    await recoverEnrollment(enrollIO());
    if (loadRec()) throw new Error("already enrolled locally");
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const userId = crypto.getRandomValues(new Uint8Array(16));
    const cred = await navigator.credentials.create({
      publicKey: {
        rp: { name: "2FA Vault", id: "localhost" },
        user: { id: userId, name: "vault", displayName: "vault" },
        challenge,
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: { residentKey: "required", userVerification: "required" },
        extensions: { prf: { eval: { first: PRF_SALT } } },
      },
    });
    prf = toUint8(await prfFrom(cred));
    if (!prf) {
      const get = await navigator.credentials.get({
        publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          rpId: "localhost",
          allowCredentials: [{ type: "public-key", id: cred.rawId }],
          userVerification: "required",
          extensions: { prf: { eval: { first: PRF_SALT } } },
        },
      });
      prf = toUint8(await prfFrom(get));
    }
    if (!prf) throw new Error("authenticator did not return PRF");

    const webauthnP256 = await compressedES256PublicKey(cred.response);
    const derivedAuth = await deriveDirectP256(prf);
    scalar = derivedAuth.scalar;
    if (bytesToHex(webauthnP256) === bytesToHex(derivedAuth.pub)) {
      throw new Error("direct-auth P-256 collided with WebAuthn credential P-256");
    }
    hot = crypto.getRandomValues(new Uint8Array(32));
    const hotPub = secp256k1.getPublicKey(hot, true);
    const derived = bytesToHex(hotPub);
    const kek = await deriveKEK(prf);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, kek, hot);
    const rec = {
      credId: bytesToHex(cred.rawId),
      webauthnP256: bytesToHex(webauthnP256),
      directP256: bytesToHex(derivedAuth.pub),
      hotPub: derived,
      nonce: bytesToHex(nonce),
      ciphertext: bytesToHex(ct),
      operationalAddress: "",
      operationalScript: "",
      tweakedProviderXOnly: "",
    };
    stagePending(localStorage, rec);
    await api("/v1/register", {
      credentialId: rec.credId,
      webauthnP256: rec.webauthnP256,
      directP256: rec.directP256,
      hotPub: rec.hotPub,
    });
    const st = await refresh();
    assertHotPub(derived, rec.hotPub, st.hotPub);
    assertDirectP256(bytesToHex(derivedAuth.pub), rec.directP256, st.directP256);
    rec.tweakedProviderXOnly = assertTweakedProvider("", st.tweakedProviderXOnly);
    rec.operationalAddress = st.operationalAddress || "";
    rec.operationalScript = st.operationalScript || "";
    stagePending(localStorage, rec);
    promotePending(localStorage);
    $("out").textContent = "enrolled; fund the Operational address shown in status";
  } finally {
    zeroBytes(prf, scalar, hot);
  }
}

function operationalFrom(rec, st) {
  return {
    operationalScriptHex: rec.operationalScript || st.operationalScript || "",
    operationalAddress: rec.operationalAddress || st.operationalAddress || "",
  };
}

async function prepareDraft() {
  const rec = loadRec();
  if (!rec) throw new Error("enroll first");
  const st = await refresh();
  assertHotPub(rec.hotPub, rec.hotPub, st.hotPub);
  const intent = readIntent();
  const draft = await api("/v1/draft", intent);
  const parsed = validateDraftPSBT({
    draftB64: draft.psbt,
    prevTxHex: intent.prevTxHex,
    vout: intent.vout,
    recipientScript: intent.recipientScript,
    recipientAmount: intent.recipientAmount,
    fee: intent.fee,
    ...operationalFrom(rec, st),
  });
  reviewed = { intent, draft, parsed, rec, st };
  $("view-review").hidden = false;
  showParsed(parsed);
  return reviewed;
}

function requireFrozenReview() {
  if (!reviewed) throw new Error("review the spend first");
  if (intentKey(readIntent()) !== intentKey(reviewed.intent)) {
    reviewed = null;
    if ($("view-review")) $("view-review").hidden = true;
    throw new Error("intent changed after review; review again");
  }
}

async function ceremony() {
  let prf;
  let scalar;
  let hot;
  try {
    const rec = loadRec();
    if (!rec) throw new Error("enroll first");
    requireFrozenReview();
    const intent = reviewed.intent;
    const { draft, st } = reviewed;
    const pre = await api("/v1/preflight", { psbt: draft.psbt });
    const challenge = hexToBytes(pre.challenge);
    const get = await navigator.credentials.get({
      publicKey: {
        challenge,
        rpId: "localhost",
        allowCredentials: [{ type: "public-key", id: hexToBytes(rec.credId) }],
        userVerification: "required",
        extensions: { prf: { eval: { first: PRF_SALT } } },
      },
    });
    requireFrozenReview();
    let live = await api("/v1/status");
    assertHotPub(rec.hotPub, rec.hotPub, live.hotPub);
    assertDirectP256(rec.directP256, rec.directP256, live.directP256);
    assertTweakedProvider(rec.tweakedProviderXOnly, live.tweakedProviderXOnly);
    prf = toUint8(await prfFrom(get));
    if (!prf) throw new Error("PRF missing");
    const assertion = {
      credentialId: rec.credId,
      clientDataJSON: bytesToHex(get.response.clientDataJSON),
      authenticatorData: bytesToHex(get.response.authenticatorData),
      signature: bytesToHex(get.response.signature),
    };
    const derivedAuth = await deriveDirectP256(prf);
    scalar = derivedAuth.scalar;
    assertDirectP256(bytesToHex(derivedAuth.pub), rec.directP256, live.directP256);
    const directSig = bytesToHex(signDirectP256(scalar, challenge));
    const bound = await api("/v1/bind", { psbt: draft.psbt, directSig, ...assertion });
    const parsed = validateBoundPSBT({
      draftB64: draft.psbt,
      boundB64: bound.psbt,
      prevTxHex: intent.prevTxHex,
      vout: intent.vout,
      recipientScript: intent.recipientScript,
      recipientAmount: intent.recipientAmount,
      fee: intent.fee,
      directSig,
      ...operationalFrom(rec, st),
    });
    showParsed(parsed);
    const kek = await deriveKEK(prf);
    hot = new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: hexToBytes(rec.nonce) },
      kek,
      hexToBytes(rec.ciphertext),
    ));
    const derived = bytesToHex(secp256k1.getPublicKey(hot, true));
    requireFrozenReview();
    live = await api("/v1/status");
    assertHotPub(derived, rec.hotPub, live.hotPub);
    assertDirectP256(rec.directP256, rec.directP256, live.directP256);
    assertTweakedProvider(rec.tweakedProviderXOnly, live.tweakedProviderXOnly);
    const signed = hotSignPSBT(bound.psbt, hot);
    const out = await api("/v1/authorize", { psbt: signed, ...assertion });
    const authorized = validateAuthorizedPSBT({
      submittedB64: signed,
      authorizedB64: out.signedPsbt,
      hotPubHex: rec.hotPub,
      tweakedProviderXOnly: rec.tweakedProviderXOnly,
    });
    const expectedTxid = authorized.transactionId;
    const challengeHex = bytesToHex(challenge);
    let published = null;
    try {
      published = await api("/v1/publish", { challenge: challengeHex });
    } catch (err) {
      if (!/publisher not configured/.test(err.message)) throw err;
    }
    if (published && published.txid !== expectedTxid) {
      throw new Error("published txid does not match the browser-authorized transaction");
    }
    if (published && Number(published.confirmations) === 0) {
      const demo = await demoInfo();
      if (demo && demo.demo) {
        await api("/v1/demo/mine", { blocks: 1 });
        const confirmed = await api("/v1/tx?challenge=" + challengeHex);
        if (confirmed.txid !== published.txid) {
          throw new Error("mined txid does not match published txid");
        }
        if (Number(confirmed.confirmations) < 1) {
          throw new Error("expected at least one confirmation after demo mine");
        }
        published = confirmed;
      }
    }
    $("out").textContent = JSON.stringify({
      authorized: { replay: out.replay },
      published,
      challenge: challengeHex,
      expectedTxid,
    }, null, 2);
    await refresh();
  } finally {
    zeroBytes(prf, scalar, hot);
  }
}

async function fundOperational() {
  const funded = await api("/v1/demo/fund", { amount: 100000 });
  if (Number(funded.confirmations) < 1) {
    throw new Error("funded prevout is unconfirmed");
  }
  $("prevtx").value = funded.prevTxHex;
  $("vout").value = String(funded.vout);
  if (funded.sinkScript) $("dest").value = funded.sinkScript;
  if (!$("amount").value) $("amount").value = "20000";
  $("out").textContent = JSON.stringify(funded, null, 2);
  reviewed = null;
  if ($("view-review")) $("view-review").hidden = true;
}

async function demoReject(kind) {
  const rec = loadRec();
  if (!rec) throw new Error("enroll first");
  try {
    if (kind === "over-budget") {
      await api("/v1/draft", { ...readIntent(), recipientAmount: 50001 });
      $("out").textContent = "over-budget unexpectedly accepted";
      return;
    }
    if (kind === "intent-changed") {
      if (!reviewed) throw new Error("review first");
      $("amount").value = String(Number($("amount").value || 0) + 1);
      requireFrozenReview();
      return;
    }
    throw new Error("unknown rejection demo");
  } catch (err) {
    $("out").textContent = err.message;
  }
}

function toUint8(value) {
  if (!value) return null;
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  return null;
}

function handle(fn) {
  runExclusive(fn).catch((e) => { $("out").textContent = e.message; });
}

$("btn-enroll").onclick = () => handle(enroll);
$("btn-review").onclick = () => handle(prepareDraft);
$("btn-sign").onclick = () => handle(ceremony);
if ($("btn-fund")) $("btn-fund").onclick = () => handle(fundOperational);
if ($("btn-reject-cap")) $("btn-reject-cap").onclick = () => handle(() => demoReject("over-budget"));
if ($("btn-reject-intent")) $("btn-reject-intent").onclick = () => handle(() => demoReject("intent-changed"));

async function bootstrap() {
  setBusy(true);
  try {
    try {
      await recoverEnrollment(enrollIO());
    } catch (e) {
      $("out").textContent = e.message;
    }
    try {
      await refresh();
    } catch (e) {
      $("status").textContent = e.message;
    }
  } finally {
    setBusy(false);
  }
}

bootstrap();
