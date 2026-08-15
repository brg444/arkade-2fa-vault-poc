import { expect, test } from "bun:test";
import { compressedES256PublicKey } from "./webauthnkey.js";

async function fixture() {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const spki = await crypto.subtle.exportKey("spki", pair.publicKey);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return { spki, raw };
}

test("imports an ES256 SPKI and compresses the exported P-256 point", async () => {
  const { spki, raw } = await fixture();
  const compressed = await compressedES256PublicKey({
    getPublicKeyAlgorithm: () => -7,
    getPublicKey: () => spki,
  });
  expect(compressed.length).toBe(33);
  expect(compressed[0]).toBe((raw[64] & 1) === 1 ? 0x03 : 0x02);
  expect([...compressed.subarray(1)]).toEqual([...raw.subarray(1, 33)]);
});

test("rejects a non-ES256 credential before parsing key bytes", async () => {
  const { spki } = await fixture();
  await expect(compressedES256PublicKey({
    getPublicKeyAlgorithm: () => -257,
    getPublicKey: () => spki,
  })).rejects.toThrow(/ES256/);
});

test("rejects malformed data instead of slicing an SPKI suffix", async () => {
  const fake = new Uint8Array(80);
  fake.set([0x04], 15);
  await expect(compressedES256PublicKey({
    getPublicKeyAlgorithm: () => -7,
    getPublicKey: () => fake.buffer,
  })).rejects.toThrow();
});
