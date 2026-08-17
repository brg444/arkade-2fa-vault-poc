import { secp256k1 } from "./vendor/secp256k1.js";
import {
  deriveDirectP256,
  signDirectP256,
  zeroBytes,
} from "./directauth.js";
import {
  assertDirectP256,
  assertPhoneRoutineBIP340Pub,
  assertArkadeChallenge,
  bytesEqual,
  bytesToHex,
  DUST_SATS,
  hexToBytes,
  phoneRoutineSignPSBT,
  MAX_MONEY_SATS,
  MAX_PREV_TX_BYTES,
  parseExactSats,
  parseExactVout,
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
  assertDescriptorIdentity,
  assertPinnedDepositOutputs,
} from "./enrollstore.js";
import { createAuthorizeRetryState } from "./authorizeretry.js";
import { compressedES256PublicKey } from "./webauthnkey.js";

const PRF_SALT = new TextEncoder().encode("arkade-2fa-vault/prf/v1");
const HKDF_INFO = new TextEncoder().encode("arkade-2fa-vault/kek/v1");
const SIGNED_CHALLENGES_STORE = "vault-signed-challenges-v1";
const MAX_API_RESPONSE_BYTES = 1024 * 1024;

const $ = (id) => document.getElementById(id);

let reviewed = null;
let busy = false;
const authorizeRetry = createAuthorizeRetryState();

const BUSY_CONTROLS = [
  "btn-enroll", "btn-fund", "btn-review", "btn-sign",
  "btn-reject-cap", "btn-reject-intent",
  "dest", "amount", "fee", "prevtx", "vout", "bootstrap-token",
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

async function api(path, body, extraHeaders = {}) {
  const bodyJSON = body == null ? null : JSON.stringify(body);
  return apiEncoded(path, bodyJSON, extraHeaders);
}

async function apiEncoded(path, bodyJSON, extraHeaders = {}) {
  const hasBody = bodyJSON != null;
  const res = await fetch(path, {
    method: hasBody ? "POST" : "GET",
    headers: hasBody
      ? { "Content-Type": "application/json", Accept: "application/json", ...extraHeaders }
      : { Accept: "application/json", ...extraHeaders },
    body: hasBody ? bodyJSON : undefined,
  });
  const text = await readBoundedResponse(res, MAX_API_RESPONSE_BYTES);
  let data;
  try { data = JSON.parse(text); } catch { throw new Error(text); }
  if (!res.ok) throw new Error(data.error || text);
  return data;
}

async function readBoundedResponse(res, maxBytes) {
  const declared = Number(res.headers.get("Content-Length"));
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw new Error("API response too large");
  }
  if (!res.body) throw new Error("API response body missing");
  const reader = res.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let total = 0;
  let text = "";
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel("response too large");
        throw new Error("API response too large");
      }
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
    return text;
  } finally {
    reader.releaseLock();
  }
}

function loadRec() {
  return loadMain(localStorage);
}

function enrollIO() {
  const bootstrapToken = $("bootstrap-token")?.value || "";
  return {
    storage: localStorage,
    register: (body) => api(
      "/v1/register",
      body,
      bootstrapToken ? { "X-Vault-Enrollment-Token": bootstrapToken } : {},
    ),
    status: () => api("/v1/status"),
  };
}

function readIntent() {
  const prevTxHex = $("prevtx").value.trim();
  const recipientScript = $("dest").value.trim();
  // Validate lengths and encodings before any request or large decode.
  hexToBytes(prevTxHex, MAX_PREV_TX_BYTES);
  hexToBytes(recipientScript, 10_000);
  const vout = parseExactVout($("vout").value);
  const amount = parseExactSats($("amount").value, "recipient amount", DUST_SATS);
  const fee = parseExactSats($("fee").value, "fee");
  if (amount.bigint + fee.bigint > MAX_MONEY_SATS) {
    throw new Error("recipient amount plus fee exceeds MAX_MONEY");
  }
  return {
    prevTxHex,
    vout: vout.text,
    recipientScript,
    recipientAmount: amount.text,
    fee: fee.text,
  };
}

function draftRequest(intent) {
  const vout = parseExactVout(intent.vout);
  const amount = parseExactSats(intent.recipientAmount, "recipient amount", DUST_SATS);
  const fee = parseExactSats(intent.fee, "fee");
  return {
    ...intent,
    vout: vout.number,
    recipientAmount: amount.number,
    fee: fee.number,
  };
}

function intentKey(intent) {
  return JSON.stringify(intent);
}

async function refresh() {
  const st = await api("/v1/status");
  const demo = await demoInfo();
  const rec = loadRec();
  if (rec?.phoneRoutineBip340Pub && st.phoneRoutineBip340Pub) assertPhoneRoutineBIP340Pub(rec.phoneRoutineBip340Pub, rec.phoneRoutineBip340Pub, st.phoneRoutineBip340Pub);
  if (rec?.phoneDirectP256) assertDirectP256(rec.phoneDirectP256, rec.phoneDirectP256, st.phoneDirectP256);
  if (rec) reconcileSignerIdentity(rec, st);
  const deposits = rec?.operationalAddress ? assertPinnedDepositOutputs(rec, st) : null;
  if (deposits) {
    st.operationalAddress = deposits.operationalAddress;
    st.operationalScript = deposits.operationalScript;
    st.savingsAddress = deposits.savingsAddress;
  }
  $("status").textContent = JSON.stringify({
    ...st,
    savingsExcludesRoutineCosigners: Boolean(deposits?.savingsAddress),
    preflightChallengeTrust: "browser independently recomputes the witness-masked Arkade sighash and requires an exact preflight match",
  }, null, 2);
  if ($("savings-note")) {
    $("savings-note").textContent = deposits?.savingsAddress
      ? "Savings excludes PhoneRoutineBIP340, VaultCosigner, and ArkadeCosigner."
      : "";
  }
  toggleDemo(demo);
  return st;
}

function reconcileSignerIdentity(rec, status) {
  const hasDescriptor = rec && Object.prototype.hasOwnProperty.call(rec, "externalOwnerWalletPub");
  return assertDescriptorIdentity(hasDescriptor ? rec : null, status);
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
  let phoneRoutineSecret;
  try {
    const recovery = await recoverEnrollment(enrollIO());
    if (recovery.action === "pending-requires-user-presence") {
      await recoverPendingEnrollment(recovery.pending);
      return;
    }
    if (loadRec()) {
      if ($("bootstrap-token")) $("bootstrap-token").value = "";
      $("out").textContent = "enrollment recovered";
      return;
    }
    const deployment = await refresh();
    const rpId = requireRPID(deployment);
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const userId = crypto.getRandomValues(new Uint8Array(16));
    const cred = await navigator.credentials.create({
      publicKey: {
        rp: { name: "2FA Vault", id: rpId },
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
          rpId,
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
    phoneRoutineSecret = randomPhoneRoutineSecret();
    const phoneRoutineBip340Pub = secp256k1.getPublicKey(phoneRoutineSecret, true);
    const derived = bytesToHex(phoneRoutineBip340Pub);
    const kek = await deriveKEK(prf);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, kek, phoneRoutineSecret);
    const rec = {
      credId: bytesToHex(cred.rawId),
      webauthnP256: bytesToHex(webauthnP256),
      phoneDirectP256: bytesToHex(derivedAuth.pub),
      phoneRoutineBip340Pub: derived,
      nonce: bytesToHex(nonce),
      ciphertext: bytesToHex(ct),
      operationalAddress: "",
      operationalScript: "",
    };
    stagePending(localStorage, rec);
    await enrollIO().register({
      credentialId: rec.credId,
      webauthnP256: rec.webauthnP256,
      phoneDirectP256: rec.phoneDirectP256,
      phoneRoutineBip340Pub: rec.phoneRoutineBip340Pub,
    });
    if ($("bootstrap-token")) $("bootstrap-token").value = "";
    const st = await refresh();
    assertPhoneRoutineBIP340Pub(derived, rec.phoneRoutineBip340Pub, st.phoneRoutineBip340Pub);
    assertDirectP256(bytesToHex(derivedAuth.pub), rec.phoneDirectP256, st.phoneDirectP256);
    Object.assign(rec, reconcileSignerIdentity(null, st));
    rec.operationalAddress = st.operationalAddress || "";
    rec.operationalScript = st.operationalScript || "";
    rec.savingsAddress = st.savingsAddress || "";
    stagePending(localStorage, rec);
    promotePending(localStorage);
    await refresh();
    $("out").textContent = "enrolled; fund the pinned Operational address";
  } finally {
    zeroBytes(prf, scalar, phoneRoutineSecret);
  }
}

async function recoverPendingEnrollment(rec) {
  let prf;
  let scalar;
  let phoneRoutineSecret;
  try {
    const deployment = await refresh();
    const rpId = requireRPID(deployment);
    const get = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rpId,
        allowCredentials: [{ type: "public-key", id: hexToBytes(rec.credId, 1024) }],
        userVerification: "required",
        extensions: { prf: { eval: { first: PRF_SALT } } },
      },
    });
    if (!bytesEqual(get.rawId, hexToBytes(rec.credId, 1024))) {
      throw new Error("recovery credential does not match the pending enrollment");
    }
    prf = toUint8(await prfFrom(get));
    if (!prf) throw new Error("PRF missing during enrollment recovery");
    const derivedAuth = await deriveDirectP256(prf);
    scalar = derivedAuth.scalar;
    assertDirectP256(bytesToHex(derivedAuth.pub), rec.phoneDirectP256, rec.phoneDirectP256);
    const kek = await deriveKEK(prf);
    phoneRoutineSecret = new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: hexToBytes(rec.nonce, 12) },
      kek,
      hexToBytes(rec.ciphertext, 48),
    ));
    const phoneRoutineBip340Pub = bytesToHex(secp256k1.getPublicKey(phoneRoutineSecret, true));
    assertPhoneRoutineBIP340Pub(phoneRoutineBip340Pub, rec.phoneRoutineBip340Pub, rec.phoneRoutineBip340Pub);
    await enrollIO().register({
      credentialId: rec.credId,
      webauthnP256: rec.webauthnP256,
      phoneDirectP256: rec.phoneDirectP256,
      phoneRoutineBip340Pub: rec.phoneRoutineBip340Pub,
    });
    if ($("bootstrap-token")) $("bootstrap-token").value = "";
    const st = await refresh();
    assertPhoneRoutineBIP340Pub(phoneRoutineBip340Pub, rec.phoneRoutineBip340Pub, st.phoneRoutineBip340Pub);
    assertDirectP256(rec.phoneDirectP256, rec.phoneDirectP256, st.phoneDirectP256);
    const signerIdentity = reconcileSignerIdentity(rec, st);
    const next = {
      ...rec,
      operationalAddress: st.operationalAddress || "",
      operationalScript: st.operationalScript || "",
      savingsAddress: st.savingsAddress || "",
      ...signerIdentity,
    };
    stagePending(localStorage, next);
    promotePending(localStorage);
    await refresh();
    $("out").textContent = "pending enrollment recovered after fresh user verification";
  } finally {
    zeroBytes(prf, scalar, phoneRoutineSecret);
  }
}

function operationalFrom(rec, st) {
  return {
    operationalScriptHex: rec.operationalScript || st.operationalScript || "",
    operationalAddress: rec.operationalAddress || st.operationalAddress || "",
    network: rec.network || st.network,
  };
}

async function prepareDraft() {
  const rec = loadRec();
  if (!rec) throw new Error("enroll first");
  const st = await refresh();
  assertPhoneRoutineBIP340Pub(rec.phoneRoutineBip340Pub, rec.phoneRoutineBip340Pub, st.phoneRoutineBip340Pub);
  const intent = readIntent();
  authorizeRetry.clearUnless(intentKey(intent));
  const draft = await api("/v1/draft", draftRequest(intent));
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
    invalidateReviewedIntent();
    throw new Error("intent changed after review; review again");
  }
}

function invalidateReviewedIntent() {
  reviewed = null;
  authorizeRetry.clear();
  if ($("view-review")) $("view-review").hidden = true;
}

async function ceremony() {
  let prf;
  let scalar;
  let phoneRoutineSecret;
  try {
    const rec = loadRec();
    if (!rec) throw new Error("enroll first");
    requireFrozenReview();
    const intent = reviewed.intent;
    const { draft, st } = reviewed;
    const reviewKey = intentKey(intent);
    if (await resumeAuthorization(rec, reviewKey)) return;
    const rpId = requireRPID(st);
    const pre = await api("/v1/preflight", { psbt: draft.psbt });
    const challengeHex = assertArkadeChallenge(reviewed.parsed.arkadeChallenge, pre.challenge);
    assertChallengeUnused(challengeHex);
    const challenge = hexToBytes(challengeHex, 32);
    const get = await navigator.credentials.get({
      publicKey: {
        challenge,
        rpId,
        allowCredentials: [{ type: "public-key", id: hexToBytes(rec.credId) }],
        userVerification: "required",
        extensions: { prf: { eval: { first: PRF_SALT } } },
      },
    });
    requireFrozenReview();
    let live = await api("/v1/status");
    assertPhoneRoutineBIP340Pub(rec.phoneRoutineBip340Pub, rec.phoneRoutineBip340Pub, live.phoneRoutineBip340Pub);
    assertDirectP256(rec.phoneDirectP256, rec.phoneDirectP256, live.phoneDirectP256);
    reconcileSignerIdentity(rec, live);
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
    assertDirectP256(bytesToHex(derivedAuth.pub), rec.phoneDirectP256, live.phoneDirectP256);
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
    phoneRoutineSecret = new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: hexToBytes(rec.nonce) },
      kek,
      hexToBytes(rec.ciphertext),
    ));
    const derived = bytesToHex(secp256k1.getPublicKey(phoneRoutineSecret, true));
    requireFrozenReview();
    live = await api("/v1/status");
    assertPhoneRoutineBIP340Pub(derived, rec.phoneRoutineBip340Pub, live.phoneRoutineBip340Pub);
    assertDirectP256(rec.phoneDirectP256, rec.phoneDirectP256, live.phoneDirectP256);
    reconcileSignerIdentity(rec, live);
    const signed = phoneRoutineSignPSBT(bound.psbt, phoneRoutineSecret);
    if (bytesToHex(challenge) !== challengeHex) throw new Error("Arkade challenge changed during ceremony");
    authorizeRetry.stage(
      reviewKey,
      { psbt: signed, ...assertion },
      {
        submittedB64: signed,
        phoneRoutineBip340PubHex: rec.phoneRoutineBip340Pub,
        tweakedVaultCosignerXOnly: rec.tweakedVaultCosignerXOnly,
        tweakedArkadeCosignerXOnly: rec.tweakedArkadeCosignerXOnly,
      },
      challengeHex,
    );
    const completed = await authorizePending(reviewKey);
    return finishAuthorized(completed);
  } finally {
    zeroBytes(prf, scalar, phoneRoutineSecret);
  }
}

async function resumeAuthorization(rec, reviewKey) {
  const completed = authorizeRetry.completedFor(reviewKey);
  if (completed) {
    await finishAuthorized(completed);
    return true;
  }
  if (!authorizeRetry.pendingFor(reviewKey)) return false;
  const live = await api("/v1/status");
  assertPhoneRoutineBIP340Pub(rec.phoneRoutineBip340Pub, rec.phoneRoutineBip340Pub, live.phoneRoutineBip340Pub);
  assertDirectP256(rec.phoneDirectP256, rec.phoneDirectP256, live.phoneDirectP256);
  reconcileSignerIdentity(rec, live);
  const resumed = await authorizePending(reviewKey);
  await finishAuthorized(resumed);
  return true;
}

async function authorizePending(reviewKey) {
  const pending = authorizeRetry.pendingFor(reviewKey);
  if (!pending) throw new Error("authorize retry state missing");
  // bodyJSON is the one serialization staged before the first POST. Keeping
  // it in page memory lets a public-signer timeout resume the server's exact
    // reserved PSBT without generating another WebAuthn, PhoneDirectP256, or
    // PhoneRoutineBIP340 signature.
  // signature.
  const out = await apiEncoded("/v1/authorize", pending.bodyJSON);
  const authorized = validateAuthorizedPSBT({
    ...pending.validation,
    authorizedB64: out.signedPsbt,
  });
  return authorizeRetry.markAuthorized(reviewKey, {
    challengeHex: pending.challengeHex,
    expectedTxid: authorized.transactionId,
    replay: out.replay,
  });
}

async function finishAuthorized(completed) {
  const {
    challengeHex,
    expectedTxid,
    replay,
  } = completed;
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
    authorized: { replay },
    published,
    challenge: challengeHex,
    expectedTxid,
  }, null, 2);
  rememberChallenge(challengeHex);
  authorizeRetry.clear();
  await refresh();
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
  invalidateReviewedIntent();
}

async function demoReject(kind) {
  const rec = loadRec();
  if (!rec) throw new Error("enroll first");
  try {
    if (kind === "over-budget") {
      await api("/v1/draft", { ...draftRequest(readIntent()), recipientAmount: 50001 });
      $("out").textContent = "over-budget unexpectedly accepted";
      return;
    }
    if (kind === "intent-changed") {
      if (!reviewed) throw new Error("review first");
      $("amount").value = String(BigInt($("amount").value || "0") + 1n);
      requireFrozenReview();
      return;
    }
    throw new Error("unknown rejection demo");
  } catch (err) {
    $("out").textContent = err.message;
  }
}

function randomPhoneRoutineSecret() {
  if (secp256k1.utils && typeof secp256k1.utils.randomPrivateKey === "function") {
    return secp256k1.utils.randomPrivateKey();
  }
  for (let i = 0; i < 256; i++) {
    const scalar = crypto.getRandomValues(new Uint8Array(32));
    if (secp256k1.utils.isValidPrivateKey(scalar)) return scalar;
    zeroBytes(scalar);
  }
  throw new Error("phone routine scalar out of range");
}

function toUint8(value) {
  if (!value) return null;
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  return null;
}

function requireRPID(status) {
  const rpId = String(status?.rpId || "").toLowerCase();
  if (!rpId || rpId !== location.hostname.toLowerCase()) {
    throw new Error("deployment RP ID does not match this signing client host");
  }
  if (status?.clientOrigin !== location.origin) {
    throw new Error("deployment origin does not match this signing client origin");
  }
  return rpId;
}

function signedChallenges() {
  try {
    const parsed = JSON.parse(sessionStorage.getItem(SIGNED_CHALLENGES_STORE) || "[]");
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((value) => /^[0-9a-f]{64}$/.test(String(value))).slice(-128);
  } catch {
    return [];
  }
}

function assertChallengeUnused(challenge) {
  if (signedChallenges().includes(challenge)) {
    throw new Error("this Arkade challenge was already completed in this browser session");
  }
}

function rememberChallenge(challenge) {
  const values = signedChallenges();
  if (!values.includes(challenge)) values.push(challenge);
  sessionStorage.setItem(SIGNED_CHALLENGES_STORE, JSON.stringify(values.slice(-128)));
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
for (const id of ["dest", "amount", "fee", "prevtx", "vout"]) {
  if ($(id)) $(id).addEventListener("input", invalidateReviewedIntent);
}

async function bootstrap() {
  setBusy(true);
  try {
    try {
      const recovery = await recoverEnrollment(enrollIO());
      if (recovery.action === "pending-requires-user-presence") {
        $("out").textContent = "pending enrollment found; click Create passkey + encrypted phoneRoutineSecret key to recover with user verification";
      }
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
