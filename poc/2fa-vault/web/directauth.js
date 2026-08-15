import { p256 } from "./vendor/p256.js";

export const DIRECT_P256_HKDF_PREFIX = new TextEncoder().encode("arkade-2fa-vault/direct-p256/v1");

export function hkdfInfo(counter) {
  if (!Number.isInteger(counter) || counter < 0 || counter > 255) {
    throw new Error("HKDF counter must be an integer in 0..255");
  }
  const info = new Uint8Array(DIRECT_P256_HKDF_PREFIX.length + 4);
  info.set(DIRECT_P256_HKDF_PREFIX);
  info[info.length - 4] = (counter >>> 24) & 0xff;
  info[info.length - 3] = (counter >>> 16) & 0xff;
  info[info.length - 2] = (counter >>> 8) & 0xff;
  info[info.length - 1] = counter & 0xff;
  return info;
}

export async function deriveDirectP256(prf) {
  const ikm = requireBytes(prf, "prf");
  if (ikm.length !== 32) throw new Error("prf must be exactly 32 bytes");
  const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  for (let counter = 0; counter <= 255; counter++) {
    const scalar = new Uint8Array(await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: hkdfInfo(counter) },
      key,
      256,
    ));
    if (p256.utils.isValidPrivateKey(scalar)) {
      return { scalar, pub: p256.getPublicKey(scalar, true), counter };
    }
    zeroBytes(scalar);
  }
  throw new Error("direct-auth P-256 scalar out of range");
}

export function signDirectP256(scalar, digest) {
  if (!p256.utils.isValidPrivateKey(requireBytes(scalar, "direct-auth scalar"))) {
    throw new Error("invalid direct-auth scalar");
  }
  const msg = requireBytes(digest, "digest");
  if (msg.length !== 32) throw new Error("Arkade digest must be 32 bytes");
  const sig = p256.sign(msg, scalar, { prehash: false, lowS: true }).toCompactRawBytes();
  if (!(sig instanceof Uint8Array) || sig.length !== 64) {
    throw new Error("direct signature must be 64 compact bytes");
  }
  return sig;
}

export function verifyDirectP256(pub, digest, signature) {
  const key = requireBytes(pub, "direct-auth pub");
  const msg = requireBytes(digest, "digest");
  const sig = requireBytes(signature, "signature");
  if (key.length !== 33) throw new Error("direct-auth pub must be 33 bytes");
  if (msg.length !== 32) throw new Error("Arkade digest must be 32 bytes");
  if (sig.length !== 64) throw new Error("direct signature must be 64 compact bytes");
  return p256.verify(sig, msg, key, { prehash: false, lowS: true });
}

export function zeroBytes(...arrs) {
  for (const a of arrs) {
    if (a instanceof Uint8Array) a.fill(0);
  }
}

function requireBytes(value, name) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  throw new Error(`${name} required`);
}
