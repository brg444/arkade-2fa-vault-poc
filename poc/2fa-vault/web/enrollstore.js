import { assertDirectP256, assertHotPub } from "./psbtcheck.js";

export const STORE = "vault-hot-v1";
export const STORE_PENDING = "vault-hot-v1-pending";

export function loadMain(storage) {
  const rec = readJSON(storage, STORE);
  if (rec) requireCompleteRecord(rec);
  return rec;
}

export function loadPending(storage) {
  return readJSON(storage, STORE_PENDING);
}

export function stagePending(storage, rec) {
  requireRegistrationRecord(rec);
  storage.setItem(STORE_PENDING, JSON.stringify(rec));
}

export function promotePending(storage) {
  const pending = loadPending(storage);
  if (!pending) throw new Error("no pending enrollment");
  requireCompleteRecord(pending);
  const main = loadMain(storage);
  if (main) {
    if (!sameEnrollmentTuple(main, pending)) {
      throw new Error("pending enrollment does not match local record");
    }
    storage.removeItem(STORE_PENDING);
    return main;
  }
  storage.setItem(STORE, JSON.stringify(pending));
  storage.removeItem(STORE_PENDING);
  return pending;
}

export function sameEnrollmentTuple(a, b) {
  return hexEq(a?.credId, b?.credId) &&
    hexEq(a?.webauthnP256, b?.webauthnP256) &&
    hexEq(a?.directP256, b?.directP256) &&
    hexEq(a?.hotPub, b?.hotPub) &&
    hexEq(a?.tweakedProviderXOnly, b?.tweakedProviderXOnly);
}

export async function recoverEnrollment({ storage, register, status }) {
  const pending = loadPending(storage);
  const main = loadMain(storage);
  if (!pending) return { action: "none" };
  if (main) {
    if (sameEnrollmentTuple(main, pending)) {
      storage.removeItem(STORE_PENDING);
      return { action: "cleared-duplicate-pending" };
    }
    throw new Error("pending enrollment does not match local record");
  }
  await register({
    credentialId: pending.credId,
    webauthnP256: pending.webauthnP256,
    directP256: pending.directP256,
    hotPub: pending.hotPub,
  });
  const st = await status();
  assertHotPub(pending.hotPub, pending.hotPub, st.hotPub);
  assertDirectP256(pending.directP256, pending.directP256, st.directP256);
  assertTweakedProvider(pending.tweakedProviderXOnly, st.tweakedProviderXOnly);
  const next = {
    ...pending,
    operationalAddress: st.operationalAddress || "",
    operationalScript: st.operationalScript || "",
    tweakedProviderXOnly: requireXOnly(st.tweakedProviderXOnly, "status tweaked provider"),
  };
  stagePending(storage, next);
  promotePending(storage);
  return { action: "retried-and-promoted" };
}

function requireCompleteRecord(rec) {
  requireRegistrationRecord(rec);
  requireXOnly(rec.tweakedProviderXOnly, "persisted tweaked provider");
}

function requireRegistrationRecord(rec) {
  if (!rec || typeof rec !== "object") throw new Error("incomplete enrollment record");
  for (const key of ["credId", "webauthnP256", "directP256", "hotPub", "nonce", "ciphertext"]) {
    if (!rec[key]) throw new Error("incomplete enrollment record");
  }
}

export function assertTweakedProvider(persisted, status) {
  const live = requireXOnly(status, "status tweaked provider");
  if (persisted && requireXOnly(persisted, "persisted tweaked provider") !== live) {
    throw new Error("persisted tweaked provider does not match vault status");
  }
  return live;
}

function requireXOnly(value, name) {
  const hex = String(value || "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error(name);
  return hex;
}

function readJSON(storage, key) {
  const raw = storage.getItem(key);
  if (!raw) return null;
  return JSON.parse(raw);
}

function hexEq(a, b) {
  const x = String(a || "").toLowerCase();
  const y = String(b || "").toLowerCase();
  return /^[0-9a-f]+$/.test(x) && x.length % 2 === 0 && x === y;
}
