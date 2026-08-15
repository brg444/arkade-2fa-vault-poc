import { expect, test } from "bun:test";
import { p256 } from "./vendor/p256.js";
import {
  DIRECT_P256_HKDF_PREFIX,
  deriveDirectP256,
  hkdfInfo,
  signDirectP256,
  verifyDirectP256,
  zeroBytes,
} from "./directauth.js";

const P256_N = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
const HALF_N = P256_N >> 1n;

function prfFixture(tag = 1) {
  const out = new Uint8Array(32);
  out[0] = 0xa1;
  out[31] = tag;
  return out;
}

function digestFixture(tag = 7) {
  const out = new Uint8Array(32);
  out.fill(0x11);
  out[0] = tag;
  return out;
}

function bytesToBigInt(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
}

test("HKDF info is prefix || uint32be(counter)", () => {
  const info0 = hkdfInfo(0);
  const info1 = hkdfInfo(1);
  const info255 = hkdfInfo(255);
  expect(info0.length).toBe(DIRECT_P256_HKDF_PREFIX.length + 4);
  expect(info0.slice(0, DIRECT_P256_HKDF_PREFIX.length)).toEqual(DIRECT_P256_HKDF_PREFIX);
  expect(Array.from(info0.slice(-4))).toEqual([0, 0, 0, 0]);
  expect(Array.from(info1.slice(-4))).toEqual([0, 0, 0, 1]);
  expect(Array.from(info255.slice(-4))).toEqual([0, 0, 0, 255]);
  expect(() => hkdfInfo(-1)).toThrow(/counter/);
  expect(() => hkdfInfo(256)).toThrow(/counter/);
  expect(() => hkdfInfo(1.5)).toThrow(/counter/);
});

test("derivation is deterministic for the same PRF", async () => {
  const prf = prfFixture(1);
  const a = await deriveDirectP256(prf);
  const b = await deriveDirectP256(prf);
  expect(a.counter).toBe(b.counter);
  expect(a.pub).toEqual(b.pub);
  expect(a.scalar).toEqual(b.scalar);
  expect(p256.utils.isValidPrivateKey(a.scalar)).toBe(true);
});

test("derivation is domain-separated from a different HKDF info prefix", async () => {
  const prf = prfFixture(2);
  const canonical = await deriveDirectP256(prf);
  const key = await crypto.subtle.importKey("raw", prf, "HKDF", false, ["deriveBits"]);
  const otherInfo = new Uint8Array(DIRECT_P256_HKDF_PREFIX.length + 4);
  otherInfo.set(new TextEncoder().encode("arkade-2fa-vault/kek/v1"));
  const other = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: otherInfo },
    key,
    256,
  ));
  expect(other).not.toEqual(canonical.scalar);
});

test("derived public key matches the scalar", async () => {
  const derived = await deriveDirectP256(prfFixture(3));
  expect(derived.pub).toEqual(p256.getPublicKey(derived.scalar, true));
  expect(derived.pub.length).toBe(33);
});

test("sign produces a 64-byte low-S signature that verifies", async () => {
  const derived = await deriveDirectP256(prfFixture(4));
  const digest = digestFixture();
  const sig = signDirectP256(derived.scalar, digest);
  expect(sig).toBeInstanceOf(Uint8Array);
  expect(sig.length).toBe(64);
  expect(bytesToBigInt(sig.slice(32)) <= HALF_N).toBe(true);
  expect(verifyDirectP256(derived.pub, digest, sig)).toBe(true);
});

test("high-S signatures are rejected", async () => {
  const derived = await deriveDirectP256(prfFixture(8));
  const digest = digestFixture();
  const low = signDirectP256(derived.scalar, digest);
  const s = bytesToBigInt(low.slice(32));
  expect(s > 0n && s <= HALF_N).toBe(true);
  const highS = P256_N - s;
  expect(highS > HALF_N).toBe(true);
  const high = new Uint8Array(low);
  const hex = highS.toString(16).padStart(64, "0");
  for (let i = 0; i < 32; i++) high[32 + i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  expect(verifyDirectP256(derived.pub, digest, high)).toBe(false);
  expect(p256.verify(high, digest, derived.pub, { prehash: false, lowS: false })).toBe(true);
});

test("tampered signature and wrong digest are rejected", async () => {
  const derived = await deriveDirectP256(prfFixture(5));
  const digest = digestFixture();
  const sig = signDirectP256(derived.scalar, digest);
  const tampered = new Uint8Array(sig);
  tampered[0] ^= 0x01;
  expect(verifyDirectP256(derived.pub, digest, tampered)).toBe(false);
  const other = digestFixture(9);
  expect(verifyDirectP256(derived.pub, other, sig)).toBe(false);
});

test("hard-coded DirectP256 derivation vector", async () => {
  const prf = Uint8Array.from({ length: 32 }, () => 0x11);
  const derived = await deriveDirectP256(prf);
  expect(derived.counter).toBe(0);
  expect(Buffer.from(derived.pub).toString("hex")).toBe(
    "0338b6980ba51016c1ab513104ce3dbe169f52dc6359456f6f4460e2140320f67f",
  );
  expect(Buffer.from(derived.scalar).toString("hex")).toBe(
    "22d2028c339cc8b3f8bd1b808b95111c95989a90713913cc76c44e9be2c83796",
  );
});

test("zero and invalid inputs are rejected", async () => {
  await expect(deriveDirectP256(undefined)).rejects.toThrow(/prf/);
  await expect(deriveDirectP256(new Uint8Array())).rejects.toThrow(/32 bytes/);
  await expect(deriveDirectP256(new Uint8Array(31))).rejects.toThrow(/32 bytes/);
  expect(() => signDirectP256(new Uint8Array(32), digestFixture())).toThrow(/scalar/);
  expect(() => signDirectP256(undefined, digestFixture())).toThrow(/scalar/);
  const derived = await deriveDirectP256(prfFixture(6));
  expect(() => signDirectP256(derived.scalar, new Uint8Array(31))).toThrow(/digest/);
  expect(() => signDirectP256(derived.scalar, undefined)).toThrow(/digest/);
  expect(() => verifyDirectP256(derived.pub, digestFixture(), new Uint8Array(63))).toThrow(/64/);
});

test("zeroBytes overwrites secret arrays", () => {
  const secret = new Uint8Array([1, 2, 3, 4]);
  zeroBytes(secret, undefined, new Uint8Array([9]));
  expect(Array.from(secret)).toEqual([0, 0, 0, 0]);
});
