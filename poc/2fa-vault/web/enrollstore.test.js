import { expect, test } from "bun:test";
import {
  STORE,
  STORE_PENDING,
  assertArkadeEmulatorIdentity,
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
    directP256: "03" + "cc".repeat(32),
    hotPub: "02" + "dd".repeat(32),
    nonce: "ee".repeat(12),
    ciphertext: "ff".repeat(48),
    tweakedProviderXOnly: "11".repeat(32),
    arkadeEmulatorBasePub: "03" + "22".repeat(32),
    tweakedArkadeXOnly: "33".repeat(32),
    arkadeEmulatorOrigin: "",
    arkadeEmulatorVersion: "",
    network: "regtest",
    operationalAddress: "",
    operationalScript: "",
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
  expect(loadMain(storage).hotPub).toBe(rec().hotPub);
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
  expect(sameEnrollmentTuple(rec({ hotPub: "02" + "dd".repeat(32) }), rec({ hotPub: "02" + "ee".repeat(32) }))).toBe(false);
  expect(sameEnrollmentTuple(rec({ nonce: "01".repeat(12) }), rec({ nonce: "02".repeat(12) }))).toBe(false);
  expect(sameEnrollmentTuple(rec({ ciphertext: "01".repeat(48) }), rec({ ciphertext: "02".repeat(48) }))).toBe(false);
  expect(sameEnrollmentTuple(rec({ arkadeEmulatorBasePub: "02" + "44".repeat(32) }), rec())).toBe(false);
  expect(sameEnrollmentTuple(rec({ tweakedArkadeXOnly: "44".repeat(32) }), rec())).toBe(false);
  expect(sameEnrollmentTuple(rec({ arkadeEmulatorVersion: "v2" }), rec())).toBe(false);
});

test("pre-registration pending records may omit the Arkade identity only as a complete group", () => {
  const storage = memoryStorage();
  const pending = rec();
  for (const key of [
    "arkadeEmulatorBasePub",
    "tweakedArkadeXOnly",
    "arkadeEmulatorOrigin",
    "arkadeEmulatorVersion",
    "network",
  ]) delete pending[key];
  stagePending(storage, pending);
  expect(loadPending(storage).arkadeEmulatorBasePub).toBeUndefined();

  pending.arkadeEmulatorBasePub = "03" + "22".repeat(32);
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
  expect(result.pending.hotPub).toBe(rec().hotPub);
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

test("main enrollment records require a pinned tweaked provider", () => {
  const storage = memoryStorage();
  storage.setItem(STORE, JSON.stringify(rec({ tweakedProviderXOnly: "" })));
  expect(() => loadMain(storage)).toThrow(/persisted tweaked provider/);
});

test("main enrollment records require the full pinned Arkade emulator identity", () => {
  for (const field of [
    "arkadeEmulatorBasePub",
    "tweakedArkadeXOnly",
    "arkadeEmulatorOrigin",
    "arkadeEmulatorVersion",
    "network",
  ]) {
    const storage = memoryStorage();
    const broken = rec();
    delete broken[field];
    storage.setItem(STORE, JSON.stringify(broken));
    expect(() => loadMain(storage)).toThrow(/Arkade emulator.*incomplete/);
  }
});

test("Arkade emulator status reconciliation pins base, tweak, origin, version, and network", () => {
  const persisted = rec({
    arkadeEmulatorOrigin: "https://arkade.example",
    arkadeEmulatorVersion: "v1.2.3",
    network: "mutinynet",
  });
  const status = {
    arkadeEmulatorBasePub: persisted.arkadeEmulatorBasePub.toUpperCase(),
    tweakedArkadeXOnly: persisted.tweakedArkadeXOnly.toUpperCase(),
    arkadeEmulatorOrigin: persisted.arkadeEmulatorOrigin,
    arkadeEmulatorVersion: persisted.arkadeEmulatorVersion,
    network: persisted.network,
  };
  expect(assertArkadeEmulatorIdentity(persisted, status)).toEqual({
    arkadeEmulatorBasePub: persisted.arkadeEmulatorBasePub,
    tweakedArkadeXOnly: persisted.tweakedArkadeXOnly,
    arkadeEmulatorOrigin: persisted.arkadeEmulatorOrigin,
    arkadeEmulatorVersion: persisted.arkadeEmulatorVersion,
    network: persisted.network,
  });

  for (const [field, replacement] of [
    ["arkadeEmulatorBasePub", "02" + "44".repeat(32)],
    ["tweakedArkadeXOnly", "44".repeat(32)],
    ["arkadeEmulatorOrigin", "https://other.example"],
    ["arkadeEmulatorVersion", "v9"],
    ["network", "regtest"],
  ]) {
    expect(() => assertArkadeEmulatorIdentity(persisted, { ...status, [field]: replacement }))
      .toThrow(/does not match vault status/);
  }
});

test("Arkade emulator status identity fails closed on malformed or unattested public identity", () => {
  const persisted = rec({
    arkadeEmulatorOrigin: "https://arkade.example",
    arkadeEmulatorVersion: "v1",
    network: "mutinynet",
  });
  expect(() => assertArkadeEmulatorIdentity(persisted, {
    ...persisted,
    arkadeEmulatorOrigin: "http://arkade.example",
  })).toThrow(/canonical HTTPS origin/);
  expect(() => assertArkadeEmulatorIdentity(persisted, {
    ...persisted,
    arkadeEmulatorVersion: "",
  })).toThrow(/required outside regtest/);
  expect(() => assertArkadeEmulatorIdentity(persisted, {
    ...persisted,
    arkadeEmulatorBasePub: "04" + "22".repeat(32),
  })).toThrow(/base pub/);

  const regtest = rec();
  const live = { ...regtest };
  delete live.arkadeEmulatorOrigin;
  delete live.arkadeEmulatorVersion;
  expect(assertArkadeEmulatorIdentity(regtest, live).arkadeEmulatorOrigin).toBe("");
});
