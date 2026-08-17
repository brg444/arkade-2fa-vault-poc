// V3 deliberately uses new keys. V1/V2 records described different Taproot
// trees and must never be reinterpreted as the ExternalOwnerWallet v3 policy.
export const STORE = "arkade-vault-enrollment-v3";
export const STORE_PENDING = "arkade-vault-enrollment-v3-pending";
export const FIRST_VAULT_ID = "operational-vault-v1";

export function mainStoreKey(vaultId) {
  const id = vaultId || FIRST_VAULT_ID;
  return id === FIRST_VAULT_ID ? STORE : `${STORE}:${id}`;
}

export function pendingStoreKey(vaultId) {
  const id = vaultId || FIRST_VAULT_ID;
  return id === FIRST_VAULT_ID ? STORE_PENDING : `${STORE_PENDING}:${id}`;
}

export function loadMain(storage, vaultId) {
  const id = vaultId || FIRST_VAULT_ID;
  const rec = readJSON(storage, mainStoreKey(id)) ||
    (id === FIRST_VAULT_ID ? readJSON(storage, STORE) : null);
  if (rec) requireCompleteRecord(rec);
  return rec;
}

export function loadPending(storage, vaultId) {
  const id = vaultId || FIRST_VAULT_ID;
  const rec = readJSON(storage, pendingStoreKey(id)) ||
    (id === FIRST_VAULT_ID ? readJSON(storage, STORE_PENDING) : null);
  if (rec) requireRegistrationRecord(rec);
  return rec;
}

export function stagePending(storage, rec, vaultId) {
  requireRegistrationRecord(rec);
  storage.setItem(pendingStoreKey(vaultId || rec?.vaultId), JSON.stringify(rec));
}

export function promotePending(storage, vaultId) {
  const pending = loadPending(storage, vaultId);
  if (!pending) throw new Error("no pending enrollment");
  requireCompleteRecord(pending);
  const id = vaultId || pending.vaultId;
  const main = loadMain(storage, id);
  if (main) {
    if (!sameEnrollmentTuple(main, pending)) {
      throw new Error("pending enrollment does not match local record");
    }
    storage.removeItem(pendingStoreKey(id));
    return main;
  }
  storage.setItem(mainStoreKey(id), JSON.stringify(pending));
  storage.removeItem(pendingStoreKey(id));
  return pending;
}

export function sameEnrollmentTuple(a, b) {
  return hexEq(a?.credId, b?.credId) &&
    hexEq(a?.webauthnP256, b?.webauthnP256) &&
    hexEq(a?.phoneDirectP256, b?.phoneDirectP256) &&
    hexEq(a?.phoneRoutineBip340Pub, b?.phoneRoutineBip340Pub) &&
    hexEq(a?.nonce, b?.nonce) &&
    hexEq(a?.ciphertext, b?.ciphertext) &&
    optionalHexEq(a?.operationalScript, b?.operationalScript) &&
    String(a?.operationalAddress || "") === String(b?.operationalAddress || "") &&
    String(a?.savingsAddress || "") === String(b?.savingsAddress || "") &&
    optionalHexEq(a?.externalOwnerWalletPub, b?.externalOwnerWalletPub) &&
    optionalHexEq(a?.recoveryKeyPub, b?.recoveryKeyPub) &&
    optionalHexEq(a?.vaultCosignerBasePub, b?.vaultCosignerBasePub) &&
    optionalHexEq(a?.tweakedVaultCosignerXOnly, b?.tweakedVaultCosignerXOnly) &&
    optionalHexEq(a?.arkadeCosignerBasePub, b?.arkadeCosignerBasePub) &&
    optionalHexEq(a?.tweakedArkadeCosignerXOnly, b?.tweakedArkadeCosignerXOnly) &&
    String(a?.arkadeCosignerOrigin || "") === String(b?.arkadeCosignerOrigin || "") &&
    String(a?.arkadeCosignerVersion || "") === String(b?.arkadeCosignerVersion || "") &&
    String(a?.network || "") === String(b?.network || "") &&
    String(a?.templateVersion || "") === String(b?.templateVersion || "") &&
    String(a?.policyVersion || "") === String(b?.policyVersion || "");
}

// recoverEnrollment performs local crash reconciliation only. It deliberately
// never POSTs /register. A pending-only record must be recovered by the
// explicit enrollment button, which performs a fresh UV WebAuthn/PRF ceremony
// and proves that the encrypted PhoneRoutineBIP340/PhoneDirectP256 keys still
// match before retrying.
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
  requireDescriptorIdentity(rec, "persisted descriptor", true);
  requireHex(rec.operationalScript, "operational script", 1, 10_000);
  requireIdentityString(rec.operationalAddress, "operational address", 256, true);
  requireIdentityString(rec.savingsAddress, "savings address", 256, true);
}

function requireRegistrationRecord(rec) {
  if (!rec || typeof rec !== "object") throw new Error("incomplete enrollment record");
  requireHex(rec.credId, "credential id", 1, 1024);
  requireCompressed(rec.webauthnP256, "WebAuthn P-256");
  requireCompressed(rec.phoneDirectP256, "PhoneDirectP256");
  requireCompressed(rec.phoneRoutineBip340Pub, "PhoneRoutineBIP340 pub");
  requireHex(rec.nonce, "AES-GCM nonce", 12, 12);
  requireHex(rec.ciphertext, "wrapped PhoneRoutineBIP340 key", 48, 48);
  if (rec.operationalScript) requireHex(rec.operationalScript, "operational script", 1, 10_000);
  requireDescriptorIdentity(rec, "pending descriptor", false);
}

export function assertTweakedVaultCosigner(persisted, status) {
  const live = requireXOnly(status, "status tweaked VaultCosigner");
  if (persisted && requireXOnly(persisted, "persisted tweaked VaultCosigner") !== live) {
    throw new Error("persisted tweaked VaultCosigner does not match vault status");
  }
  return live;
}

export function assertArkadeCosignerIdentity(persisted, status) {
  const live = requireArkadeIdentity({
    ...status,
    arkadeCosignerOrigin: status?.arkadeCosignerOrigin ?? "",
    arkadeCosignerVersion: status?.arkadeCosignerVersion ?? "",
  }, "status ArkadeCosigner", true);
  if (!persisted) return live;
  const stored = requireArkadeIdentity(persisted, "persisted ArkadeCosigner", true);
  for (const field of [
    "arkadeCosignerBasePub",
    "tweakedArkadeCosignerXOnly",
    "arkadeCosignerOrigin",
    "arkadeCosignerVersion",
    "network",
  ]) {
    if (stored[field] !== live[field]) {
      throw new Error(`persisted ArkadeCosigner ${identityLabel(field)} does not match vault status`);
    }
  }
  return live;
}

const ARKADE_IDENTITY_FIELDS = [
  "arkadeCosignerBasePub",
  "tweakedArkadeCosignerXOnly",
  "arkadeCosignerOrigin",
  "arkadeCosignerVersion",
  "network",
];

function requireArkadeIdentity(value, name, required) {
  const source = value && typeof value === "object" ? value : {};
  const present = ARKADE_IDENTITY_FIELDS.filter((field) =>
    Object.prototype.hasOwnProperty.call(source, field));
  if (!required && present.length === 0) return null;
  if (present.length !== ARKADE_IDENTITY_FIELDS.length) {
    throw new Error(`${name} identity is incomplete`);
  }
  const identity = {
    arkadeCosignerBasePub: requireCompressed(source.arkadeCosignerBasePub, `${name} base pub`),
    tweakedArkadeCosignerXOnly: requireXOnly(source.tweakedArkadeCosignerXOnly, `${name} tweaked key`),
    arkadeCosignerOrigin: requireIdentityString(source.arkadeCosignerOrigin, `${name} origin`, 2048),
    arkadeCosignerVersion: requireIdentityString(source.arkadeCosignerVersion, `${name} version`, 128),
    network: requireNetwork(source.network, `${name} network`),
  };
  if (identity.network !== "regtest") {
    if (!identity.arkadeCosignerOrigin || !identity.arkadeCosignerVersion) {
      throw new Error(`${name} origin and version are required outside regtest`);
    }
    let parsed;
    try {
      parsed = new URL(identity.arkadeCosignerOrigin);
    } catch {
      throw new Error(`${name} origin must be a canonical HTTPS origin`);
    }
    if (parsed.protocol !== "https:" || parsed.origin !== identity.arkadeCosignerOrigin) {
      throw new Error(`${name} origin must be a canonical HTTPS origin`);
    }
  }
  return identity;
}

const DESCRIPTOR_IDENTITY_FIELDS = [
  "externalOwnerWalletPub",
  "recoveryKeyPub",
  "vaultCosignerBasePub",
  "tweakedVaultCosignerXOnly",
  ...ARKADE_IDENTITY_FIELDS,
  "templateVersion",
  "policyVersion",
];

export function assertDescriptorIdentity(persisted, status) {
  const live = requireDescriptorIdentity(status, "status descriptor", true);
  if (!persisted) return live;
  const stored = requireDescriptorIdentity(persisted, "persisted descriptor", true);
  for (const field of DESCRIPTOR_IDENTITY_FIELDS) {
    if (stored[field] !== live[field]) {
      throw new Error(`persisted descriptor ${field} does not match vault status`);
    }
  }
  return live;
}

export function assertPinnedDepositOutputs(persisted, status) {
  if (!persisted) throw new Error("persisted deposit outputs required");
  const storedAddress = requireIdentityString(persisted.operationalAddress, "persisted operational address", 256, true);
  const storedScript = requireHex(persisted.operationalScript, "persisted operational script", 1, 10_000);
  const storedSavings = requireIdentityString(persisted.savingsAddress, "persisted savings address", 256, true);
  const liveAddress = requireIdentityString(status?.operationalAddress, "status operational address", 256, true);
  const liveScript = requireHex(status?.operationalScript, "status operational script", 1, 10_000);
  const liveSavings = requireIdentityString(status?.savingsAddress, "status savings address", 256, true);
  if (storedAddress !== liveAddress || storedScript !== liveScript || storedSavings !== liveSavings) {
    throw new Error("persisted deposit outputs do not match vault status");
  }
  return {
    operationalAddress: storedAddress,
    operationalScript: storedScript,
    savingsAddress: storedSavings,
  };
}

function requireDescriptorIdentity(value, name, required) {
  const source = value && typeof value === "object" ? value : {};
  const present = DESCRIPTOR_IDENTITY_FIELDS.filter((field) =>
    Object.prototype.hasOwnProperty.call(source, field));
  if (!required && present.length === 0) return null;
  if (present.length !== DESCRIPTOR_IDENTITY_FIELDS.length) {
    throw new Error(`${name} identity is incomplete`);
  }
  const arkade = requireArkadeIdentity(source, `${name} ArkadeCosigner`, true);
  const identity = {
    externalOwnerWalletPub: requireCompressed(source.externalOwnerWalletPub, `${name} ExternalOwnerWallet`),
    recoveryKeyPub: requireCompressed(source.recoveryKeyPub, `${name} RecoveryKey`),
    vaultCosignerBasePub: requireCompressed(source.vaultCosignerBasePub, `${name} VaultCosigner base`),
    tweakedVaultCosignerXOnly: requireXOnly(source.tweakedVaultCosignerXOnly, `${name} tweaked VaultCosigner`),
    ...arkade,
    templateVersion: requireIdentityString(source.templateVersion, `${name} template version`, 256, true),
    policyVersion: requireIdentityString(source.policyVersion, `${name} policy version`, 256, true),
  };
  const secpRoles = [
    source.phoneRoutineBip340Pub ? requireCompressed(source.phoneRoutineBip340Pub, `${name} PhoneRoutineBIP340`).slice(2) : null,
    identity.externalOwnerWalletPub.slice(2),
    identity.recoveryKeyPub.slice(2),
    identity.vaultCosignerBasePub.slice(2),
    identity.tweakedVaultCosignerXOnly,
    identity.arkadeCosignerBasePub.slice(2),
    identity.tweakedArkadeCosignerXOnly,
  ].filter(Boolean);
  if (new Set(secpRoles).size !== secpRoles.length) {
    throw new Error(`${name} secp256k1 roles are not x-only independent`);
  }
  return identity;
}

function requireIdentityString(value, name, maxLength, nonempty = false) {
  if (typeof value !== "string" || value.length > maxLength || (nonempty && value.length === 0) || value.trim() !== value || /[\u0000-\u001f\u007f]/.test(value)) {
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
    arkadeCosignerBasePub: "base key",
    tweakedArkadeCosignerXOnly: "tweaked key",
    arkadeCosignerOrigin: "origin",
    arkadeCosignerVersion: "version",
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
