export const STORE = "vault-hot-v1";
export const STORE_PENDING = "vault-hot-v1-pending";

export function loadMain(storage) {
  const rec = readJSON(storage, STORE);
  if (rec) requireCompleteRecord(rec);
  return rec;
}

export function loadPending(storage) {
  const rec = readJSON(storage, STORE_PENDING);
  if (rec) requireRegistrationRecord(rec);
  return rec;
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
    hexEq(a?.nonce, b?.nonce) &&
    hexEq(a?.ciphertext, b?.ciphertext) &&
    optionalHexEq(a?.operationalScript, b?.operationalScript) &&
    String(a?.operationalAddress || "") === String(b?.operationalAddress || "") &&
    optionalHexEq(a?.tweakedProviderXOnly, b?.tweakedProviderXOnly) &&
    optionalHexEq(a?.arkadeEmulatorBasePub, b?.arkadeEmulatorBasePub) &&
    optionalHexEq(a?.tweakedArkadeXOnly, b?.tweakedArkadeXOnly) &&
    String(a?.arkadeEmulatorOrigin || "") === String(b?.arkadeEmulatorOrigin || "") &&
    String(a?.arkadeEmulatorVersion || "") === String(b?.arkadeEmulatorVersion || "") &&
    String(a?.network || "") === String(b?.network || "");
}

// recoverEnrollment performs local crash reconciliation only. It deliberately
// never POSTs /register. A pending-only record must be recovered by the
// explicit enrollment button, which performs a fresh UV WebAuthn/PRF ceremony
// and proves that the encrypted hot/direct keys still match before retrying.
export async function recoverEnrollment({ storage }) {
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
  return { action: "pending-requires-user-presence", pending };
}

function requireCompleteRecord(rec) {
  requireRegistrationRecord(rec);
  requireXOnly(rec.tweakedProviderXOnly, "persisted tweaked provider");
  requireArkadeEmulatorIdentity(rec, "persisted Arkade emulator", true);
}

function requireRegistrationRecord(rec) {
  if (!rec || typeof rec !== "object") throw new Error("incomplete enrollment record");
  requireHex(rec.credId, "credential id", 1, 1024);
  requireCompressed(rec.webauthnP256, "WebAuthn P-256");
  requireCompressed(rec.directP256, "Direct P-256");
  requireCompressed(rec.hotPub, "hot pub");
  requireHex(rec.nonce, "AES-GCM nonce", 12, 12);
  requireHex(rec.ciphertext, "wrapped hot key", 48, 48);
  if (rec.operationalScript) requireHex(rec.operationalScript, "operational script", 1, 10_000);
  if (rec.tweakedProviderXOnly) requireXOnly(rec.tweakedProviderXOnly, "persisted tweaked provider");
  requireArkadeEmulatorIdentity(rec, "pending Arkade emulator", false);
}

export function assertTweakedProvider(persisted, status) {
  const live = requireXOnly(status, "status tweaked provider");
  if (persisted && requireXOnly(persisted, "persisted tweaked provider") !== live) {
    throw new Error("persisted tweaked provider does not match vault status");
  }
  return live;
}

export function assertArkadeEmulatorIdentity(persisted, status) {
  const live = requireArkadeEmulatorIdentity({
    ...status,
    arkadeEmulatorOrigin: status?.arkadeEmulatorOrigin ?? "",
    arkadeEmulatorVersion: status?.arkadeEmulatorVersion ?? "",
  }, "status Arkade emulator", true);
  if (!persisted) return live;
  const stored = requireArkadeEmulatorIdentity(persisted, "persisted Arkade emulator", true);
  for (const field of [
    "arkadeEmulatorBasePub",
    "tweakedArkadeXOnly",
    "arkadeEmulatorOrigin",
    "arkadeEmulatorVersion",
    "network",
  ]) {
    if (stored[field] !== live[field]) {
      throw new Error(`persisted Arkade emulator ${identityLabel(field)} does not match vault status`);
    }
  }
  return live;
}

const ARKADE_IDENTITY_FIELDS = [
  "arkadeEmulatorBasePub",
  "tweakedArkadeXOnly",
  "arkadeEmulatorOrigin",
  "arkadeEmulatorVersion",
  "network",
];

function requireArkadeEmulatorIdentity(value, name, required) {
  const source = value && typeof value === "object" ? value : {};
  const present = ARKADE_IDENTITY_FIELDS.filter((field) =>
    Object.prototype.hasOwnProperty.call(source, field));
  if (!required && present.length === 0) return null;
  if (present.length !== ARKADE_IDENTITY_FIELDS.length) {
    throw new Error(`${name} identity is incomplete`);
  }
  const identity = {
    arkadeEmulatorBasePub: requireCompressed(source.arkadeEmulatorBasePub, `${name} base pub`),
    tweakedArkadeXOnly: requireXOnly(source.tweakedArkadeXOnly, `${name} tweaked key`),
    arkadeEmulatorOrigin: requireIdentityString(source.arkadeEmulatorOrigin, `${name} origin`, 2048),
    arkadeEmulatorVersion: requireIdentityString(source.arkadeEmulatorVersion, `${name} version`, 128),
    network: requireNetwork(source.network, `${name} network`),
  };
  if (identity.network !== "regtest") {
    if (!identity.arkadeEmulatorOrigin || !identity.arkadeEmulatorVersion) {
      throw new Error(`${name} origin and version are required outside regtest`);
    }
    let parsed;
    try {
      parsed = new URL(identity.arkadeEmulatorOrigin);
    } catch {
      throw new Error(`${name} origin must be a canonical HTTPS origin`);
    }
    if (parsed.protocol !== "https:" || parsed.origin !== identity.arkadeEmulatorOrigin) {
      throw new Error(`${name} origin must be a canonical HTTPS origin`);
    }
  }
  return identity;
}

function requireIdentityString(value, name, maxLength) {
  if (typeof value !== "string" || value.length > maxLength || value.trim() !== value || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new Error(name);
  }
  return value;
}

function requireNetwork(value, name) {
  if (value !== "regtest" && value !== "mutinynet") throw new Error(name);
  return value;
}

function identityLabel(field) {
  return ({
    arkadeEmulatorBasePub: "base key",
    tweakedArkadeXOnly: "tweaked key",
    arkadeEmulatorOrigin: "origin",
    arkadeEmulatorVersion: "version",
    network: "network",
  })[field];
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

function optionalHexEq(a, b) {
  const x = String(a || "");
  const y = String(b || "");
  return x === "" && y === "" || hexEq(x, y);
}

function requireCompressed(value, name) {
  const hex = String(value || "").toLowerCase();
  if (!/^(02|03)[0-9a-f]{64}$/.test(hex)) throw new Error(name);
  return hex;
}

function requireHex(value, name, minBytes, maxBytes) {
  const hex = String(value || "").toLowerCase();
  if (!/^[0-9a-f]+$/.test(hex) || hex.length % 2 !== 0 ||
      hex.length < minBytes * 2 || hex.length > maxBytes * 2) {
    throw new Error(name);
  }
  return hex;
}
