export async function compressedES256PublicKey(response, subtle = crypto.subtle) {
  if (!response || typeof response.getPublicKeyAlgorithm !== "function" ||
      response.getPublicKeyAlgorithm() !== -7) {
    throw new Error("credential public key must use ES256");
  }
  if (typeof response.getPublicKey !== "function") {
    throw new Error("credential public key unavailable");
  }
  const spki = response.getPublicKey();
  if (!(spki instanceof ArrayBuffer) && !ArrayBuffer.isView(spki)) {
    throw new Error("credential public key must be SPKI bytes");
  }
  const key = await subtle.importKey(
    "spki",
    spki,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"],
  );
  const raw = new Uint8Array(await subtle.exportKey("raw", key));
  if (raw.length !== 65 || raw[0] !== 0x04) {
    throw new Error("credential public key must be uncompressed P-256");
  }
  const out = new Uint8Array(33);
  out[0] = (raw[64] & 1) === 1 ? 0x03 : 0x02;
  out.set(raw.subarray(1, 33), 1);
  return out;
}
