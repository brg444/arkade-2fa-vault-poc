import { expect, test } from "bun:test";
import {
  STORE,
  STORE_PENDING,
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
    webauthnP256: "bb",
    directP256: "cc",
    hotPub: "dd",
    nonce: "ee",
    ciphertext: "ff",
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
  expect(loadMain(storage).hotPub).toBe("dd");
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
  expect(sameEnrollmentTuple(rec({ hotPub: "dd" }), rec({ hotPub: "ee" }))).toBe(false);
});

test("recover retries exact register then promotes when only pending exists", async () => {
  const storage = memoryStorage();
  stagePending(storage, rec());
  let registered = null;
  const result = await recoverEnrollment({
    storage,
    register: async (body) => { registered = body; },
    status: async () => ({
      hotPub: "dd",
      directP256: "cc",
      operationalAddress: "bcrt1qop",
      operationalScript: "5120aa",
    }),
  });
  expect(result.action).toBe("retried-and-promoted");
  expect(registered).toEqual({
    credentialId: "aa",
    webauthnP256: "bb",
    directP256: "cc",
    hotPub: "dd",
  });
  expect(loadMain(storage).operationalAddress).toBe("bcrt1qop");
  expect(loadPending(storage)).toBeNull();
});

test("recover refuses to overwrite or discard a pending/main mismatch", async () => {
  const storage = memoryStorage();
  storage.setItem(STORE, JSON.stringify(rec({ credId: "11" })));
  storage.setItem(STORE_PENDING, JSON.stringify(rec({ credId: "22" })));
  let called = false;
  await expect(recoverEnrollment({
    storage,
    register: async () => { called = true; },
    status: async () => ({ hotPub: "dd", directP256: "cc" }),
  })).rejects.toThrow(/does not match local record/);
  expect(called).toBe(false);
  expect(loadMain(storage).credId).toBe("11");
  expect(loadPending(storage).credId).toBe("22");
});

test("recover rejects a status hot/direct mismatch without promoting", async () => {
  const storage = memoryStorage();
  stagePending(storage, rec());
  await expect(recoverEnrollment({
    storage,
    register: async () => {},
    status: async () => ({ hotPub: "00", directP256: "cc" }),
  })).rejects.toThrow(/hot pub/);
  expect(loadMain(storage)).toBeNull();
  expect(loadPending(storage).hotPub).toBe("dd");
});
