import { expect, test } from "bun:test";
import {
  STORE,
  STORE_PENDING,
  assertArkadeCosignerIdentity,
  assertDescriptorIdentity,
  assertPinnedDepositOutputs,
  loadMain,
  loadPending,
  promotePending,
  recoverEnrollment,
  sameEnrollmentTuple,
  stagePending,
} from "./enrollstore.js";

function memoryStorage(initial = {}) {
  const data = { ...initial };
  return {
    getItem(key) {
      return Object.prototype.hasOwnProperty.call(data, key) ? data[key] : null;
    },
    setItem(key, value) {
      data[key] = String(value);
    },
    removeItem(key) {
      delete data[key];
    },
  };
}

function rec(over = {}) {
  return {
    credId: "aa",
    webauthnP256: "02" + "bb".repeat(32),
    phoneDirectP256: "03" + "cc".repeat(32),
    phoneRoutineBip340Pub: "02" + "dd".repeat(32),
    nonce: "ee".repeat(12),
    ciphertext: "ff".repeat(48),
    externalOwnerWalletPub: "02" + "44".repeat(32),
    recoveryKeyPub: "03" + "55".repeat(32),
    vaultCosignerBasePub: "02" + "66".repeat(32),
    tweakedVaultCosignerXOnly: "11".repeat(32),
    arkadeCosignerBasePub: "03" + "22".repeat(32),
    tweakedArkadeCosignerXOnly: "33".repeat(32),
    arkadeCosignerOrigin: "",
    arkadeCosignerVersion: "",
    network: "regtest",
    templateVersion: "phone-direct-p256-routine-3of3-admin-2of2-v3",
    policyVersion: "mandatory-change-onchain-v3",
    operationalAddress: "bcrt1ptest-v3",
    operationalScript: "5120" + "77".repeat(32),
    savingsAddress: "bcrt1psavings-v3",
    ...over,
  };
}

test("stagePending writes only the pending key", () => {
  const storage = memoryStorage();
  stagePending(storage, rec());
  expect(loadPending(storage).credId).toBe("aa");
  expect(loadMain(storage)).toBeNull();
});

test("promotePending moves pending to main and removes pending", () => {
  const storage = memoryStorage();
  stagePending(storage, rec({ operationalAddress: "bcrt1q" }));
  const main = promotePending(storage);
  expect(main.operationalAddress).toBe("bcrt1q");
  expect(loadMain(storage).phoneRoutineBip340Pub).toBe(rec().phoneRoutineBip340Pub);
  expect(loadPending(storage)).toBeNull();
});

test("promotePending never overwrites a mismatched main record", () => {
  const storage = memoryStorage();
  storage.setItem(STORE, JSON.stringify(rec({ credId: "11" })));
  stagePending(storage, rec({ credId: "22" }));
  expect(() => promotePending(storage)).toThrow(/does not match local record/);
  expect(loadMain(storage).credId).toBe("11");
  expect(loadPending(storage).credId).toBe("22");
});

test("sameEnrollmentTuple is case-insensitive hex", () => {
  expect(sameEnrollmentTuple(rec({ credId: "AA" }), rec({ credId: "aa" }))).toBe(true);
  expect(sameEnrollmentTuple(rec({ phoneRoutineBip340Pub: "02" + "dd".repeat(32) }), rec({ phoneRoutineBip340Pub: "02" + "ee".repeat(32) }))).toBe(false);
  expect(sameEnrollmentTuple(rec({ nonce: "01".repeat(12) }), rec({ nonce: "02".repeat(12) }))).toBe(false);
  expect(sameEnrollmentTuple(rec({ ciphertext: "01".repeat(48) }), rec({ ciphertext: "02".repeat(48) }))).toBe(false);
  expect(sameEnrollmentTuple(rec({ arkadeCosignerBasePub: "02" + "44".repeat(32) }), rec())).toBe(false);
  expect(sameEnrollmentTuple(rec({ tweakedArkadeCosignerXOnly: "44".repeat(32) }), rec())).toBe(false);
  expect(sameEnrollmentTuple(rec({ arkadeCosignerVersion: "v2" }), rec())).toBe(false);
});

test("pre-registration pending records may omit the full descriptor identity only as a complete group", () => {
  const storage = memoryStorage();
  const pending = rec();
  for (const key of [
    "externalOwnerWalletPub",
    "recoveryKeyPub",
    "vaultCosignerBasePub",
    "tweakedVaultCosignerXOnly",
    "arkadeCosignerBasePub",
    "tweakedArkadeCosignerXOnly",
    "arkadeCosignerOrigin",
    "arkadeCosignerVersion",
    "network",
    "templateVersion",
    "policyVersion",
  ]) delete pending[key];
  stagePending(storage, pending);
  expect(loadPending(storage).arkadeCosignerBasePub).toBeUndefined();

  pending.arkadeCosignerBasePub = "03" + "22".repeat(32);
  expect(() => stagePending(storage, pending)).toThrow(/identity is incomplete/);
});

test("pending-only recovery requires explicit user presence and does not call the network", async () => {
  const storage = memoryStorage();
  stagePending(storage, rec());
  let called = false;
  const result = await recoverEnrollment({
    storage,
    register: async () => { called = true; },
    status: async () => { called = true; },
  });
  expect(result.action).toBe("pending-requires-user-presence");
  expect(result.pending.phoneRoutineBip340Pub).toBe(rec().phoneRoutineBip340Pub);
  expect(called).toBe(false);
  expect(loadMain(storage)).toBeNull();
  expect(loadPending(storage).credId).toBe("aa");
});

test("recover refuses to overwrite or discard a pending/main mismatch", async () => {
  const storage = memoryStorage();
  storage.setItem(STORE, JSON.stringify(rec({ credId: "11" })));
  storage.setItem(STORE_PENDING, JSON.stringify(rec({ credId: "22" })));
  let called = false;
  await expect(recoverEnrollment({ storage, register: async () => { called = true; } }))
    .rejects.toThrow(/does not match local record/);
  expect(called).toBe(false);
  expect(loadMain(storage).credId).toBe("11");
  expect(loadPending(storage).credId).toBe("22");
});

test("corrupted pending records are rejected before recovery", async () => {
  const storage = memoryStorage();
  storage.setItem(STORE_PENDING, JSON.stringify(rec({ nonce: "00" })));
  await expect(recoverEnrollment({ storage })).rejects.toThrow(/nonce/);
});

test("main enrollment records require a pinned tweaked VaultCosigner", () => {
  const storage = memoryStorage();
  storage.setItem(STORE, JSON.stringify(rec({ tweakedVaultCosignerXOnly: "" })));
  expect(() => loadMain(storage)).toThrow(/descriptor/);
});

test("main enrollment records require the full v3 descriptor identity", () => {
  for (const field of [
    "externalOwnerWalletPub",
    "recoveryKeyPub",
    "vaultCosignerBasePub",
    "tweakedVaultCosignerXOnly",
    "arkadeCosignerBasePub",
    "tweakedArkadeCosignerXOnly",
    "arkadeCosignerOrigin",
    "arkadeCosignerVersion",
    "network",
    "templateVersion",
    "policyVersion",
  ]) {
    const storage = memoryStorage();
    const broken = rec();
    delete broken[field];
    storage.setItem(STORE, JSON.stringify(broken));
    expect(() => loadMain(storage)).toThrow(/descriptor.*incomplete/);
  }
});

test("pinned deposit outputs reject a substituted status address", () => {
  const persisted = rec();
  expect(assertPinnedDepositOutputs(persisted, persisted)).toEqual({
    operationalAddress: persisted.operationalAddress,
    operationalScript: persisted.operationalScript,
    savingsAddress: persisted.savingsAddress,
  });
  expect(() => assertPinnedDepositOutputs(persisted, {
    ...persisted,
    operationalAddress: "bcrt1p-attacker",
  })).toThrow(/deposit outputs/);
  expect(() => assertPinnedDepositOutputs(persisted, {
    ...persisted,
    savingsAddress: "bcrt1p-attacker-savings",
  })).toThrow(/deposit outputs/);
});

test("descriptor reconciliation pins ExternalOwnerWallet, RecoveryKey, and both routine cosigners", () => {
  const persisted = rec();
  expect(assertDescriptorIdentity(persisted, { ...persisted })).toMatchObject({
    externalOwnerWalletPub: persisted.externalOwnerWalletPub,
    recoveryKeyPub: persisted.recoveryKeyPub,
    vaultCosignerBasePub: persisted.vaultCosignerBasePub,
    tweakedVaultCosignerXOnly: persisted.tweakedVaultCosignerXOnly,
  });
  for (const [field, replacement] of [
    ["externalOwnerWalletPub", "02" + "88".repeat(32)],
    ["recoveryKeyPub", "03" + "88".repeat(32)],
    ["vaultCosignerBasePub", "02" + "88".repeat(32)],
    ["tweakedVaultCosignerXOnly", "88".repeat(32)],
    ["templateVersion", "v2"],
    ["policyVersion", "v2"],
  ]) {
    expect(() => assertDescriptorIdentity(persisted, { ...persisted, [field]: replacement }))
      .toThrow(/does not match vault status|not x-only independent/);
  }
  expect(() => assertDescriptorIdentity(persisted, {
    ...persisted,
    recoveryKeyPub: persisted.externalOwnerWalletPub,
  })).toThrow(/x-only independent/);
});

test("Arkade emulator status reconciliation pins base, tweak, origin, version, and network", () => {
  const persisted = rec({
    arkadeCosignerOrigin: "https://arkade.example",
    arkadeCosignerVersion: "v1.2.3",
    network: "mutinynet",
  });
  const status = {
    arkadeCosignerBasePub: persisted.arkadeCosignerBasePub.toUpperCase(),
    tweakedArkadeCosignerXOnly: persisted.tweakedArkadeCosignerXOnly.toUpperCase(),
    arkadeCosignerOrigin: persisted.arkadeCosignerOrigin,
    arkadeCosignerVersion: persisted.arkadeCosignerVersion,
    network: persisted.network,
  };
  expect(assertArkadeCosignerIdentity(persisted, status)).toEqual({
    arkadeCosignerBasePub: persisted.arkadeCosignerBasePub,
    tweakedArkadeCosignerXOnly: persisted.tweakedArkadeCosignerXOnly,
    arkadeCosignerOrigin: persisted.arkadeCosignerOrigin,
    arkadeCosignerVersion: persisted.arkadeCosignerVersion,
    network: persisted.network,
  });

  for (const [field, replacement] of [
    ["arkadeCosignerBasePub", "02" + "44".repeat(32)],
    ["tweakedArkadeCosignerXOnly", "44".repeat(32)],
    ["arkadeCosignerOrigin", "https://other.example"],
    ["arkadeCosignerVersion", "v9"],
    ["network", "regtest"],
  ]) {
    expect(() => assertArkadeCosignerIdentity(persisted, { ...status, [field]: replacement }))
      .toThrow(/does not match vault status/);
  }
});

test("Arkade emulator status identity fails closed on malformed or unattested public identity", () => {
  const persisted = rec({
    arkadeCosignerOrigin: "https://arkade.example",
    arkadeCosignerVersion: "v1",
    network: "mutinynet",
  });
  expect(() => assertArkadeCosignerIdentity(persisted, {
    ...persisted,
    arkadeCosignerOrigin: "http://arkade.example",
  })).toThrow(/canonical HTTPS origin/);
  expect(() => assertArkadeCosignerIdentity(persisted, {
    ...persisted,
    arkadeCosignerVersion: "",
  })).toThrow(/required outside regtest/);
  expect(() => assertArkadeCosignerIdentity(persisted, {
    ...persisted,
    arkadeCosignerBasePub: "04" + "22".repeat(32),
  })).toThrow(/base pub/);

  const regtest = rec();
  const live = { ...regtest };
  delete live.arkadeCosignerOrigin;
  delete live.arkadeCosignerVersion;
  expect(assertArkadeCosignerIdentity(regtest, live).arkadeCosignerOrigin).toBe("");
});
