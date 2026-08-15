var __defProp = Object.defineProperty;
var __returnValue = (v) => v;
function __exportSetter(name, newValue) {
  this[name] = __returnValue.bind(null, newValue);
}
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, {
      get: all[name],
      enumerable: true,
      configurable: true,
      set: __exportSetter.bind(all, name)
    });
};

// node_modules/@noble/hashes/esm/_assert.js
function anumber(n) {
  if (!Number.isSafeInteger(n) || n < 0)
    throw new Error("positive integer expected, got " + n);
}
function isBytes(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
}
function abytes(b, ...lengths) {
  if (!isBytes(b))
    throw new Error("Uint8Array expected");
  if (lengths.length > 0 && !lengths.includes(b.length))
    throw new Error("Uint8Array expected of length " + lengths + ", got length=" + b.length);
}
function ahash(h) {
  if (typeof h !== "function" || typeof h.create !== "function")
    throw new Error("Hash should be wrapped by utils.wrapConstructor");
  anumber(h.outputLen);
  anumber(h.blockLen);
}
function aexists(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("Hash instance has been destroyed");
  if (checkFinished && instance.finished)
    throw new Error("Hash#digest() has already been called");
}
function aoutput(out, instance) {
  abytes(out);
  const min = instance.outputLen;
  if (out.length < min) {
    throw new Error("digestInto() expects output buffer of length at least " + min);
  }
}

// node_modules/@noble/hashes/esm/crypto.js
var crypto = typeof globalThis === "object" && "crypto" in globalThis ? globalThis.crypto : undefined;

// node_modules/@noble/hashes/esm/utils.js
/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
function createView(arr) {
  return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
function rotr(word, shift) {
  return word << 32 - shift | word >>> shift;
}
function rotl(word, shift) {
  return word << shift | word >>> 32 - shift >>> 0;
}
function utf8ToBytes(str) {
  if (typeof str !== "string")
    throw new Error("utf8ToBytes expected string, got " + typeof str);
  return new Uint8Array(new TextEncoder().encode(str));
}
function toBytes(data) {
  if (typeof data === "string")
    data = utf8ToBytes(data);
  abytes(data);
  return data;
}
function concatBytes(...arrays) {
  let sum = 0;
  for (let i = 0;i < arrays.length; i++) {
    const a = arrays[i];
    abytes(a);
    sum += a.length;
  }
  const res = new Uint8Array(sum);
  for (let i = 0, pad = 0;i < arrays.length; i++) {
    const a = arrays[i];
    res.set(a, pad);
    pad += a.length;
  }
  return res;
}

class Hash {
  clone() {
    return this._cloneInto();
  }
}
function wrapConstructor(hashCons) {
  const hashC = (msg) => hashCons().update(toBytes(msg)).digest();
  const tmp = hashCons();
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = () => hashCons();
  return hashC;
}
function randomBytes(bytesLength = 32) {
  if (crypto && typeof crypto.getRandomValues === "function") {
    return crypto.getRandomValues(new Uint8Array(bytesLength));
  }
  if (crypto && typeof crypto.randomBytes === "function") {
    return crypto.randomBytes(bytesLength);
  }
  throw new Error("crypto.getRandomValues must be defined");
}

// node_modules/@noble/hashes/esm/_md.js
function setBigUint64(view, byteOffset, value, isLE) {
  if (typeof view.setBigUint64 === "function")
    return view.setBigUint64(byteOffset, value, isLE);
  const _32n = BigInt(32);
  const _u32_max = BigInt(4294967295);
  const wh = Number(value >> _32n & _u32_max);
  const wl = Number(value & _u32_max);
  const h = isLE ? 4 : 0;
  const l = isLE ? 0 : 4;
  view.setUint32(byteOffset + h, wh, isLE);
  view.setUint32(byteOffset + l, wl, isLE);
}
function Chi(a, b, c) {
  return a & b ^ ~a & c;
}
function Maj(a, b, c) {
  return a & b ^ a & c ^ b & c;
}

class HashMD extends Hash {
  constructor(blockLen, outputLen, padOffset, isLE) {
    super();
    this.blockLen = blockLen;
    this.outputLen = outputLen;
    this.padOffset = padOffset;
    this.isLE = isLE;
    this.finished = false;
    this.length = 0;
    this.pos = 0;
    this.destroyed = false;
    this.buffer = new Uint8Array(blockLen);
    this.view = createView(this.buffer);
  }
  update(data) {
    aexists(this);
    const { view, buffer, blockLen } = this;
    data = toBytes(data);
    const len = data.length;
    for (let pos = 0;pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      if (take === blockLen) {
        const dataView = createView(data);
        for (;blockLen <= len - pos; pos += blockLen)
          this.process(dataView, pos);
        continue;
      }
      buffer.set(data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      pos += take;
      if (this.pos === blockLen) {
        this.process(view, 0);
        this.pos = 0;
      }
    }
    this.length += data.length;
    this.roundClean();
    return this;
  }
  digestInto(out) {
    aexists(this);
    aoutput(out, this);
    this.finished = true;
    const { buffer, view, blockLen, isLE } = this;
    let { pos } = this;
    buffer[pos++] = 128;
    this.buffer.subarray(pos).fill(0);
    if (this.padOffset > blockLen - pos) {
      this.process(view, 0);
      pos = 0;
    }
    for (let i = pos;i < blockLen; i++)
      buffer[i] = 0;
    setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE);
    this.process(view, 0);
    const oview = createView(out);
    const len = this.outputLen;
    if (len % 4)
      throw new Error("_sha2: outputLen should be aligned to 32bit");
    const outLen = len / 4;
    const state = this.get();
    if (outLen > state.length)
      throw new Error("_sha2: outputLen bigger than state");
    for (let i = 0;i < outLen; i++)
      oview.setUint32(4 * i, state[i], isLE);
  }
  digest() {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res;
  }
  _cloneInto(to) {
    to || (to = new this.constructor);
    to.set(...this.get());
    const { blockLen, buffer, length, finished, destroyed, pos } = this;
    to.length = length;
    to.pos = pos;
    to.finished = finished;
    to.destroyed = destroyed;
    if (length % blockLen)
      to.buffer.set(buffer);
    return to;
  }
}

// node_modules/@noble/hashes/esm/sha256.js
var SHA256_K = /* @__PURE__ */ new Uint32Array([
  1116352408,
  1899447441,
  3049323471,
  3921009573,
  961987163,
  1508970993,
  2453635748,
  2870763221,
  3624381080,
  310598401,
  607225278,
  1426881987,
  1925078388,
  2162078206,
  2614888103,
  3248222580,
  3835390401,
  4022224774,
  264347078,
  604807628,
  770255983,
  1249150122,
  1555081692,
  1996064986,
  2554220882,
  2821834349,
  2952996808,
  3210313671,
  3336571891,
  3584528711,
  113926993,
  338241895,
  666307205,
  773529912,
  1294757372,
  1396182291,
  1695183700,
  1986661051,
  2177026350,
  2456956037,
  2730485921,
  2820302411,
  3259730800,
  3345764771,
  3516065817,
  3600352804,
  4094571909,
  275423344,
  430227734,
  506948616,
  659060556,
  883997877,
  958139571,
  1322822218,
  1537002063,
  1747873779,
  1955562222,
  2024104815,
  2227730452,
  2361852424,
  2428436474,
  2756734187,
  3204031479,
  3329325298
]);
var SHA256_IV = /* @__PURE__ */ new Uint32Array([
  1779033703,
  3144134277,
  1013904242,
  2773480762,
  1359893119,
  2600822924,
  528734635,
  1541459225
]);
var SHA256_W = /* @__PURE__ */ new Uint32Array(64);

class SHA256 extends HashMD {
  constructor() {
    super(64, 32, 8, false);
    this.A = SHA256_IV[0] | 0;
    this.B = SHA256_IV[1] | 0;
    this.C = SHA256_IV[2] | 0;
    this.D = SHA256_IV[3] | 0;
    this.E = SHA256_IV[4] | 0;
    this.F = SHA256_IV[5] | 0;
    this.G = SHA256_IV[6] | 0;
    this.H = SHA256_IV[7] | 0;
  }
  get() {
    const { A, B, C, D, E, F, G, H } = this;
    return [A, B, C, D, E, F, G, H];
  }
  set(A, B, C, D, E, F, G, H) {
    this.A = A | 0;
    this.B = B | 0;
    this.C = C | 0;
    this.D = D | 0;
    this.E = E | 0;
    this.F = F | 0;
    this.G = G | 0;
    this.H = H | 0;
  }
  process(view, offset) {
    for (let i = 0;i < 16; i++, offset += 4)
      SHA256_W[i] = view.getUint32(offset, false);
    for (let i = 16;i < 64; i++) {
      const W15 = SHA256_W[i - 15];
      const W2 = SHA256_W[i - 2];
      const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
      const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10;
      SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
    }
    let { A, B, C, D, E, F, G, H } = this;
    for (let i = 0;i < 64; i++) {
      const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
      const T1 = H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i] | 0;
      const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
      const T2 = sigma0 + Maj(A, B, C) | 0;
      H = G;
      G = F;
      F = E;
      E = D + T1 | 0;
      D = C;
      C = B;
      B = A;
      A = T1 + T2 | 0;
    }
    A = A + this.A | 0;
    B = B + this.B | 0;
    C = C + this.C | 0;
    D = D + this.D | 0;
    E = E + this.E | 0;
    F = F + this.F | 0;
    G = G + this.G | 0;
    H = H + this.H | 0;
    this.set(A, B, C, D, E, F, G, H);
  }
  roundClean() {
    SHA256_W.fill(0);
  }
  destroy() {
    this.set(0, 0, 0, 0, 0, 0, 0, 0);
    this.buffer.fill(0);
  }
}
var sha256 = /* @__PURE__ */ wrapConstructor(() => new SHA256);

// node_modules/@noble/hashes/esm/hmac.js
class HMAC extends Hash {
  constructor(hash, _key) {
    super();
    this.finished = false;
    this.destroyed = false;
    ahash(hash);
    const key = toBytes(_key);
    this.iHash = hash.create();
    if (typeof this.iHash.update !== "function")
      throw new Error("Expected instance of class which extends utils.Hash");
    this.blockLen = this.iHash.blockLen;
    this.outputLen = this.iHash.outputLen;
    const blockLen = this.blockLen;
    const pad = new Uint8Array(blockLen);
    pad.set(key.length > blockLen ? hash.create().update(key).digest() : key);
    for (let i = 0;i < pad.length; i++)
      pad[i] ^= 54;
    this.iHash.update(pad);
    this.oHash = hash.create();
    for (let i = 0;i < pad.length; i++)
      pad[i] ^= 54 ^ 92;
    this.oHash.update(pad);
    pad.fill(0);
  }
  update(buf) {
    aexists(this);
    this.iHash.update(buf);
    return this;
  }
  digestInto(out) {
    aexists(this);
    abytes(out, this.outputLen);
    this.finished = true;
    this.iHash.digestInto(out);
    this.oHash.update(out);
    this.oHash.digestInto(out);
    this.destroy();
  }
  digest() {
    const out = new Uint8Array(this.oHash.outputLen);
    this.digestInto(out);
    return out;
  }
  _cloneInto(to) {
    to || (to = Object.create(Object.getPrototypeOf(this), {}));
    const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
    to = to;
    to.finished = finished;
    to.destroyed = destroyed;
    to.blockLen = blockLen;
    to.outputLen = outputLen;
    to.oHash = oHash._cloneInto(to.oHash);
    to.iHash = iHash._cloneInto(to.iHash);
    return to;
  }
  destroy() {
    this.destroyed = true;
    this.oHash.destroy();
    this.iHash.destroy();
  }
}
var hmac = (hash, key, message) => new HMAC(hash, key).update(message).digest();
hmac.create = (hash, key) => new HMAC(hash, key);

// node_modules/@noble/curves/esm/abstract/utils.js
var exports_utils = {};
__export(exports_utils, {
  validateObject: () => validateObject,
  utf8ToBytes: () => utf8ToBytes2,
  numberToVarBytesBE: () => numberToVarBytesBE,
  numberToHexUnpadded: () => numberToHexUnpadded,
  numberToBytesLE: () => numberToBytesLE,
  numberToBytesBE: () => numberToBytesBE,
  notImplemented: () => notImplemented,
  memoized: () => memoized,
  isBytes: () => isBytes2,
  inRange: () => inRange,
  hexToNumber: () => hexToNumber,
  hexToBytes: () => hexToBytes,
  equalBytes: () => equalBytes,
  ensureBytes: () => ensureBytes,
  createHmacDrbg: () => createHmacDrbg,
  concatBytes: () => concatBytes2,
  bytesToNumberLE: () => bytesToNumberLE,
  bytesToNumberBE: () => bytesToNumberBE,
  bytesToHex: () => bytesToHex,
  bitSet: () => bitSet,
  bitMask: () => bitMask,
  bitLen: () => bitLen,
  bitGet: () => bitGet,
  abytes: () => abytes2,
  abool: () => abool,
  aInRange: () => aInRange
});
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
var _0n = /* @__PURE__ */ BigInt(0);
var _1n = /* @__PURE__ */ BigInt(1);
var _2n = /* @__PURE__ */ BigInt(2);
function isBytes2(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
}
function abytes2(item) {
  if (!isBytes2(item))
    throw new Error("Uint8Array expected");
}
function abool(title, value) {
  if (typeof value !== "boolean")
    throw new Error(title + " boolean expected, got " + value);
}
var hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
function bytesToHex(bytes) {
  abytes2(bytes);
  let hex = "";
  for (let i = 0;i < bytes.length; i++) {
    hex += hexes[bytes[i]];
  }
  return hex;
}
function numberToHexUnpadded(num) {
  const hex = num.toString(16);
  return hex.length & 1 ? "0" + hex : hex;
}
function hexToNumber(hex) {
  if (typeof hex !== "string")
    throw new Error("hex string expected, got " + typeof hex);
  return hex === "" ? _0n : BigInt("0x" + hex);
}
var asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
function asciiToBase16(ch) {
  if (ch >= asciis._0 && ch <= asciis._9)
    return ch - asciis._0;
  if (ch >= asciis.A && ch <= asciis.F)
    return ch - (asciis.A - 10);
  if (ch >= asciis.a && ch <= asciis.f)
    return ch - (asciis.a - 10);
  return;
}
function hexToBytes(hex) {
  if (typeof hex !== "string")
    throw new Error("hex string expected, got " + typeof hex);
  const hl = hex.length;
  const al = hl / 2;
  if (hl % 2)
    throw new Error("hex string expected, got unpadded hex of length " + hl);
  const array = new Uint8Array(al);
  for (let ai = 0, hi = 0;ai < al; ai++, hi += 2) {
    const n1 = asciiToBase16(hex.charCodeAt(hi));
    const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
    if (n1 === undefined || n2 === undefined) {
      const char = hex[hi] + hex[hi + 1];
      throw new Error('hex string expected, got non-hex character "' + char + '" at index ' + hi);
    }
    array[ai] = n1 * 16 + n2;
  }
  return array;
}
function bytesToNumberBE(bytes) {
  return hexToNumber(bytesToHex(bytes));
}
function bytesToNumberLE(bytes) {
  abytes2(bytes);
  return hexToNumber(bytesToHex(Uint8Array.from(bytes).reverse()));
}
function numberToBytesBE(n, len) {
  return hexToBytes(n.toString(16).padStart(len * 2, "0"));
}
function numberToBytesLE(n, len) {
  return numberToBytesBE(n, len).reverse();
}
function numberToVarBytesBE(n) {
  return hexToBytes(numberToHexUnpadded(n));
}
function ensureBytes(title, hex, expectedLength) {
  let res;
  if (typeof hex === "string") {
    try {
      res = hexToBytes(hex);
    } catch (e) {
      throw new Error(title + " must be hex string or Uint8Array, cause: " + e);
    }
  } else if (isBytes2(hex)) {
    res = Uint8Array.from(hex);
  } else {
    throw new Error(title + " must be hex string or Uint8Array");
  }
  const len = res.length;
  if (typeof expectedLength === "number" && len !== expectedLength)
    throw new Error(title + " of length " + expectedLength + " expected, got " + len);
  return res;
}
function concatBytes2(...arrays) {
  let sum = 0;
  for (let i = 0;i < arrays.length; i++) {
    const a = arrays[i];
    abytes2(a);
    sum += a.length;
  }
  const res = new Uint8Array(sum);
  for (let i = 0, pad = 0;i < arrays.length; i++) {
    const a = arrays[i];
    res.set(a, pad);
    pad += a.length;
  }
  return res;
}
function equalBytes(a, b) {
  if (a.length !== b.length)
    return false;
  let diff = 0;
  for (let i = 0;i < a.length; i++)
    diff |= a[i] ^ b[i];
  return diff === 0;
}
function utf8ToBytes2(str) {
  if (typeof str !== "string")
    throw new Error("string expected");
  return new Uint8Array(new TextEncoder().encode(str));
}
var isPosBig = (n) => typeof n === "bigint" && _0n <= n;
function inRange(n, min, max) {
  return isPosBig(n) && isPosBig(min) && isPosBig(max) && min <= n && n < max;
}
function aInRange(title, n, min, max) {
  if (!inRange(n, min, max))
    throw new Error("expected valid " + title + ": " + min + " <= n < " + max + ", got " + n);
}
function bitLen(n) {
  let len;
  for (len = 0;n > _0n; n >>= _1n, len += 1)
    ;
  return len;
}
function bitGet(n, pos) {
  return n >> BigInt(pos) & _1n;
}
function bitSet(n, pos, value) {
  return n | (value ? _1n : _0n) << BigInt(pos);
}
var bitMask = (n) => (_2n << BigInt(n - 1)) - _1n;
var u8n = (data) => new Uint8Array(data);
var u8fr = (arr) => Uint8Array.from(arr);
function createHmacDrbg(hashLen, qByteLen, hmacFn) {
  if (typeof hashLen !== "number" || hashLen < 2)
    throw new Error("hashLen must be a number");
  if (typeof qByteLen !== "number" || qByteLen < 2)
    throw new Error("qByteLen must be a number");
  if (typeof hmacFn !== "function")
    throw new Error("hmacFn must be a function");
  let v = u8n(hashLen);
  let k = u8n(hashLen);
  let i = 0;
  const reset = () => {
    v.fill(1);
    k.fill(0);
    i = 0;
  };
  const h = (...b) => hmacFn(k, v, ...b);
  const reseed = (seed = u8n()) => {
    k = h(u8fr([0]), seed);
    v = h();
    if (seed.length === 0)
      return;
    k = h(u8fr([1]), seed);
    v = h();
  };
  const gen = () => {
    if (i++ >= 1000)
      throw new Error("drbg: tried 1000 values");
    let len = 0;
    const out = [];
    while (len < qByteLen) {
      v = h();
      const sl = v.slice();
      out.push(sl);
      len += v.length;
    }
    return concatBytes2(...out);
  };
  const genUntil = (seed, pred) => {
    reset();
    reseed(seed);
    let res = undefined;
    while (!(res = pred(gen())))
      reseed();
    reset();
    return res;
  };
  return genUntil;
}
var validatorFns = {
  bigint: (val) => typeof val === "bigint",
  function: (val) => typeof val === "function",
  boolean: (val) => typeof val === "boolean",
  string: (val) => typeof val === "string",
  stringOrUint8Array: (val) => typeof val === "string" || isBytes2(val),
  isSafeInteger: (val) => Number.isSafeInteger(val),
  array: (val) => Array.isArray(val),
  field: (val, object) => object.Fp.isValid(val),
  hash: (val) => typeof val === "function" && Number.isSafeInteger(val.outputLen)
};
function validateObject(object, validators, optValidators = {}) {
  const checkField = (fieldName, type, isOptional) => {
    const checkVal = validatorFns[type];
    if (typeof checkVal !== "function")
      throw new Error("invalid validator function");
    const val = object[fieldName];
    if (isOptional && val === undefined)
      return;
    if (!checkVal(val, object)) {
      throw new Error("param " + String(fieldName) + " is invalid. Expected " + type + ", got " + val);
    }
  };
  for (const [fieldName, type] of Object.entries(validators))
    checkField(fieldName, type, false);
  for (const [fieldName, type] of Object.entries(optValidators))
    checkField(fieldName, type, true);
  return object;
}
var notImplemented = () => {
  throw new Error("not implemented");
};
function memoized(fn) {
  const map = new WeakMap;
  return (arg, ...args) => {
    const val = map.get(arg);
    if (val !== undefined)
      return val;
    const computed = fn(arg, ...args);
    map.set(arg, computed);
    return computed;
  };
}

// node_modules/@noble/curves/esm/abstract/modular.js
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
var _0n2 = BigInt(0);
var _1n2 = BigInt(1);
var _2n2 = /* @__PURE__ */ BigInt(2);
var _3n = /* @__PURE__ */ BigInt(3);
var _4n = /* @__PURE__ */ BigInt(4);
var _5n = /* @__PURE__ */ BigInt(5);
var _8n = /* @__PURE__ */ BigInt(8);
var _9n = /* @__PURE__ */ BigInt(9);
var _16n = /* @__PURE__ */ BigInt(16);
function mod(a, b) {
  const result = a % b;
  return result >= _0n2 ? result : b + result;
}
function pow(num, power, modulo) {
  if (power < _0n2)
    throw new Error("invalid exponent, negatives unsupported");
  if (modulo <= _0n2)
    throw new Error("invalid modulus");
  if (modulo === _1n2)
    return _0n2;
  let res = _1n2;
  while (power > _0n2) {
    if (power & _1n2)
      res = res * num % modulo;
    num = num * num % modulo;
    power >>= _1n2;
  }
  return res;
}
function pow2(x, power, modulo) {
  let res = x;
  while (power-- > _0n2) {
    res *= res;
    res %= modulo;
  }
  return res;
}
function invert(number, modulo) {
  if (number === _0n2)
    throw new Error("invert: expected non-zero number");
  if (modulo <= _0n2)
    throw new Error("invert: expected positive modulus, got " + modulo);
  let a = mod(number, modulo);
  let b = modulo;
  let x = _0n2, y = _1n2, u = _1n2, v = _0n2;
  while (a !== _0n2) {
    const q = b / a;
    const r = b % a;
    const m = x - u * q;
    const n = y - v * q;
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  const gcd = b;
  if (gcd !== _1n2)
    throw new Error("invert: does not exist");
  return mod(x, modulo);
}
function tonelliShanks(P) {
  const legendreC = (P - _1n2) / _2n2;
  let Q, S, Z;
  for (Q = P - _1n2, S = 0;Q % _2n2 === _0n2; Q /= _2n2, S++)
    ;
  for (Z = _2n2;Z < P && pow(Z, legendreC, P) !== P - _1n2; Z++) {
    if (Z > 1000)
      throw new Error("Cannot find square root: likely non-prime P");
  }
  if (S === 1) {
    const p1div4 = (P + _1n2) / _4n;
    return function tonelliFast(Fp, n) {
      const root = Fp.pow(n, p1div4);
      if (!Fp.eql(Fp.sqr(root), n))
        throw new Error("Cannot find square root");
      return root;
    };
  }
  const Q1div2 = (Q + _1n2) / _2n2;
  return function tonelliSlow(Fp, n) {
    if (Fp.pow(n, legendreC) === Fp.neg(Fp.ONE))
      throw new Error("Cannot find square root");
    let r = S;
    let g = Fp.pow(Fp.mul(Fp.ONE, Z), Q);
    let x = Fp.pow(n, Q1div2);
    let b = Fp.pow(n, Q);
    while (!Fp.eql(b, Fp.ONE)) {
      if (Fp.eql(b, Fp.ZERO))
        return Fp.ZERO;
      let m = 1;
      for (let t2 = Fp.sqr(b);m < r; m++) {
        if (Fp.eql(t2, Fp.ONE))
          break;
        t2 = Fp.sqr(t2);
      }
      const ge = Fp.pow(g, _1n2 << BigInt(r - m - 1));
      g = Fp.sqr(ge);
      x = Fp.mul(x, ge);
      b = Fp.mul(b, g);
      r = m;
    }
    return x;
  };
}
function FpSqrt(P) {
  if (P % _4n === _3n) {
    const p1div4 = (P + _1n2) / _4n;
    return function sqrt3mod4(Fp, n) {
      const root = Fp.pow(n, p1div4);
      if (!Fp.eql(Fp.sqr(root), n))
        throw new Error("Cannot find square root");
      return root;
    };
  }
  if (P % _8n === _5n) {
    const c1 = (P - _5n) / _8n;
    return function sqrt5mod8(Fp, n) {
      const n2 = Fp.mul(n, _2n2);
      const v = Fp.pow(n2, c1);
      const nv = Fp.mul(n, v);
      const i = Fp.mul(Fp.mul(nv, _2n2), v);
      const root = Fp.mul(nv, Fp.sub(i, Fp.ONE));
      if (!Fp.eql(Fp.sqr(root), n))
        throw new Error("Cannot find square root");
      return root;
    };
  }
  if (P % _16n === _9n) {}
  return tonelliShanks(P);
}
var FIELD_FIELDS = [
  "create",
  "isValid",
  "is0",
  "neg",
  "inv",
  "sqrt",
  "sqr",
  "eql",
  "add",
  "sub",
  "mul",
  "pow",
  "div",
  "addN",
  "subN",
  "mulN",
  "sqrN"
];
function validateField(field) {
  const initial = {
    ORDER: "bigint",
    MASK: "bigint",
    BYTES: "isSafeInteger",
    BITS: "isSafeInteger"
  };
  const opts = FIELD_FIELDS.reduce((map, val) => {
    map[val] = "function";
    return map;
  }, initial);
  return validateObject(field, opts);
}
function FpPow(f, num, power) {
  if (power < _0n2)
    throw new Error("invalid exponent, negatives unsupported");
  if (power === _0n2)
    return f.ONE;
  if (power === _1n2)
    return num;
  let p = f.ONE;
  let d = num;
  while (power > _0n2) {
    if (power & _1n2)
      p = f.mul(p, d);
    d = f.sqr(d);
    power >>= _1n2;
  }
  return p;
}
function FpInvertBatch(f, nums) {
  const tmp = new Array(nums.length);
  const lastMultiplied = nums.reduce((acc, num, i) => {
    if (f.is0(num))
      return acc;
    tmp[i] = acc;
    return f.mul(acc, num);
  }, f.ONE);
  const inverted = f.inv(lastMultiplied);
  nums.reduceRight((acc, num, i) => {
    if (f.is0(num))
      return acc;
    tmp[i] = f.mul(acc, tmp[i]);
    return f.mul(acc, num);
  }, inverted);
  return tmp;
}
function nLength(n, nBitLength) {
  const _nBitLength = nBitLength !== undefined ? nBitLength : n.toString(2).length;
  const nByteLength = Math.ceil(_nBitLength / 8);
  return { nBitLength: _nBitLength, nByteLength };
}
function Field(ORDER, bitLen2, isLE = false, redef = {}) {
  if (ORDER <= _0n2)
    throw new Error("invalid field: expected ORDER > 0, got " + ORDER);
  const { nBitLength: BITS, nByteLength: BYTES } = nLength(ORDER, bitLen2);
  if (BYTES > 2048)
    throw new Error("invalid field: expected ORDER of <= 2048 bytes");
  let sqrtP;
  const f = Object.freeze({
    ORDER,
    isLE,
    BITS,
    BYTES,
    MASK: bitMask(BITS),
    ZERO: _0n2,
    ONE: _1n2,
    create: (num) => mod(num, ORDER),
    isValid: (num) => {
      if (typeof num !== "bigint")
        throw new Error("invalid field element: expected bigint, got " + typeof num);
      return _0n2 <= num && num < ORDER;
    },
    is0: (num) => num === _0n2,
    isOdd: (num) => (num & _1n2) === _1n2,
    neg: (num) => mod(-num, ORDER),
    eql: (lhs, rhs) => lhs === rhs,
    sqr: (num) => mod(num * num, ORDER),
    add: (lhs, rhs) => mod(lhs + rhs, ORDER),
    sub: (lhs, rhs) => mod(lhs - rhs, ORDER),
    mul: (lhs, rhs) => mod(lhs * rhs, ORDER),
    pow: (num, power) => FpPow(f, num, power),
    div: (lhs, rhs) => mod(lhs * invert(rhs, ORDER), ORDER),
    sqrN: (num) => num * num,
    addN: (lhs, rhs) => lhs + rhs,
    subN: (lhs, rhs) => lhs - rhs,
    mulN: (lhs, rhs) => lhs * rhs,
    inv: (num) => invert(num, ORDER),
    sqrt: redef.sqrt || ((n) => {
      if (!sqrtP)
        sqrtP = FpSqrt(ORDER);
      return sqrtP(f, n);
    }),
    invertBatch: (lst) => FpInvertBatch(f, lst),
    cmov: (a, b, c) => c ? b : a,
    toBytes: (num) => isLE ? numberToBytesLE(num, BYTES) : numberToBytesBE(num, BYTES),
    fromBytes: (bytes) => {
      if (bytes.length !== BYTES)
        throw new Error("Field.fromBytes: expected " + BYTES + " bytes, got " + bytes.length);
      return isLE ? bytesToNumberLE(bytes) : bytesToNumberBE(bytes);
    }
  });
  return Object.freeze(f);
}
function getFieldBytesLength(fieldOrder) {
  if (typeof fieldOrder !== "bigint")
    throw new Error("field order must be bigint");
  const bitLength = fieldOrder.toString(2).length;
  return Math.ceil(bitLength / 8);
}
function getMinHashLength(fieldOrder) {
  const length = getFieldBytesLength(fieldOrder);
  return length + Math.ceil(length / 2);
}
function mapHashToField(key, fieldOrder, isLE = false) {
  const len = key.length;
  const fieldLen = getFieldBytesLength(fieldOrder);
  const minLen = getMinHashLength(fieldOrder);
  if (len < 16 || len < minLen || len > 1024)
    throw new Error("expected " + minLen + "-1024 bytes of input, got " + len);
  const num = isLE ? bytesToNumberLE(key) : bytesToNumberBE(key);
  const reduced = mod(num, fieldOrder - _1n2) + _1n2;
  return isLE ? numberToBytesLE(reduced, fieldLen) : numberToBytesBE(reduced, fieldLen);
}

// node_modules/@noble/curves/esm/abstract/curve.js
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
var _0n3 = BigInt(0);
var _1n3 = BigInt(1);
function constTimeNegate(condition, item) {
  const neg = item.negate();
  return condition ? neg : item;
}
function validateW(W, bits) {
  if (!Number.isSafeInteger(W) || W <= 0 || W > bits)
    throw new Error("invalid window size, expected [1.." + bits + "], got W=" + W);
}
function calcWOpts(W, bits) {
  validateW(W, bits);
  const windows = Math.ceil(bits / W) + 1;
  const windowSize = 2 ** (W - 1);
  return { windows, windowSize };
}
function validateMSMPoints(points, c) {
  if (!Array.isArray(points))
    throw new Error("array expected");
  points.forEach((p, i) => {
    if (!(p instanceof c))
      throw new Error("invalid point at index " + i);
  });
}
function validateMSMScalars(scalars, field) {
  if (!Array.isArray(scalars))
    throw new Error("array of scalars expected");
  scalars.forEach((s, i) => {
    if (!field.isValid(s))
      throw new Error("invalid scalar at index " + i);
  });
}
var pointPrecomputes = new WeakMap;
var pointWindowSizes = new WeakMap;
function getW(P) {
  return pointWindowSizes.get(P) || 1;
}
function wNAF(c, bits) {
  return {
    constTimeNegate,
    hasPrecomputes(elm) {
      return getW(elm) !== 1;
    },
    unsafeLadder(elm, n, p = c.ZERO) {
      let d = elm;
      while (n > _0n3) {
        if (n & _1n3)
          p = p.add(d);
        d = d.double();
        n >>= _1n3;
      }
      return p;
    },
    precomputeWindow(elm, W) {
      const { windows, windowSize } = calcWOpts(W, bits);
      const points = [];
      let p = elm;
      let base = p;
      for (let window = 0;window < windows; window++) {
        base = p;
        points.push(base);
        for (let i = 1;i < windowSize; i++) {
          base = base.add(p);
          points.push(base);
        }
        p = base.double();
      }
      return points;
    },
    wNAF(W, precomputes, n) {
      const { windows, windowSize } = calcWOpts(W, bits);
      let p = c.ZERO;
      let f = c.BASE;
      const mask = BigInt(2 ** W - 1);
      const maxNumber = 2 ** W;
      const shiftBy = BigInt(W);
      for (let window = 0;window < windows; window++) {
        const offset = window * windowSize;
        let wbits = Number(n & mask);
        n >>= shiftBy;
        if (wbits > windowSize) {
          wbits -= maxNumber;
          n += _1n3;
        }
        const offset1 = offset;
        const offset2 = offset + Math.abs(wbits) - 1;
        const cond1 = window % 2 !== 0;
        const cond2 = wbits < 0;
        if (wbits === 0) {
          f = f.add(constTimeNegate(cond1, precomputes[offset1]));
        } else {
          p = p.add(constTimeNegate(cond2, precomputes[offset2]));
        }
      }
      return { p, f };
    },
    wNAFUnsafe(W, precomputes, n, acc = c.ZERO) {
      const { windows, windowSize } = calcWOpts(W, bits);
      const mask = BigInt(2 ** W - 1);
      const maxNumber = 2 ** W;
      const shiftBy = BigInt(W);
      for (let window = 0;window < windows; window++) {
        const offset = window * windowSize;
        if (n === _0n3)
          break;
        let wbits = Number(n & mask);
        n >>= shiftBy;
        if (wbits > windowSize) {
          wbits -= maxNumber;
          n += _1n3;
        }
        if (wbits === 0)
          continue;
        let curr = precomputes[offset + Math.abs(wbits) - 1];
        if (wbits < 0)
          curr = curr.negate();
        acc = acc.add(curr);
      }
      return acc;
    },
    getPrecomputes(W, P, transform) {
      let comp = pointPrecomputes.get(P);
      if (!comp) {
        comp = this.precomputeWindow(P, W);
        if (W !== 1)
          pointPrecomputes.set(P, transform(comp));
      }
      return comp;
    },
    wNAFCached(P, n, transform) {
      const W = getW(P);
      return this.wNAF(W, this.getPrecomputes(W, P, transform), n);
    },
    wNAFCachedUnsafe(P, n, transform, prev) {
      const W = getW(P);
      if (W === 1)
        return this.unsafeLadder(P, n, prev);
      return this.wNAFUnsafe(W, this.getPrecomputes(W, P, transform), n, prev);
    },
    setWindowSize(P, W) {
      validateW(W, bits);
      pointWindowSizes.set(P, W);
      pointPrecomputes.delete(P);
    }
  };
}
function pippenger(c, fieldN, points, scalars) {
  validateMSMPoints(points, c);
  validateMSMScalars(scalars, fieldN);
  if (points.length !== scalars.length)
    throw new Error("arrays of points and scalars must have equal length");
  const zero = c.ZERO;
  const wbits = bitLen(BigInt(points.length));
  const windowSize = wbits > 12 ? wbits - 3 : wbits > 4 ? wbits - 2 : wbits ? 2 : 1;
  const MASK = (1 << windowSize) - 1;
  const buckets = new Array(MASK + 1).fill(zero);
  const lastBits = Math.floor((fieldN.BITS - 1) / windowSize) * windowSize;
  let sum = zero;
  for (let i = lastBits;i >= 0; i -= windowSize) {
    buckets.fill(zero);
    for (let j = 0;j < scalars.length; j++) {
      const scalar = scalars[j];
      const wbits2 = Number(scalar >> BigInt(i) & BigInt(MASK));
      buckets[wbits2] = buckets[wbits2].add(points[j]);
    }
    let resI = zero;
    for (let j = buckets.length - 1, sumI = zero;j > 0; j--) {
      sumI = sumI.add(buckets[j]);
      resI = resI.add(sumI);
    }
    sum = sum.add(resI);
    if (i !== 0)
      for (let j = 0;j < windowSize; j++)
        sum = sum.double();
  }
  return sum;
}
function validateBasic(curve) {
  validateField(curve.Fp);
  validateObject(curve, {
    n: "bigint",
    h: "bigint",
    Gx: "field",
    Gy: "field"
  }, {
    nBitLength: "isSafeInteger",
    nByteLength: "isSafeInteger"
  });
  return Object.freeze({
    ...nLength(curve.n, curve.nBitLength),
    ...curve,
    ...{ p: curve.Fp.ORDER }
  });
}

// node_modules/@noble/curves/esm/abstract/weierstrass.js
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
function validateSigVerOpts(opts) {
  if (opts.lowS !== undefined)
    abool("lowS", opts.lowS);
  if (opts.prehash !== undefined)
    abool("prehash", opts.prehash);
}
function validatePointOpts(curve) {
  const opts = validateBasic(curve);
  validateObject(opts, {
    a: "field",
    b: "field"
  }, {
    allowedPrivateKeyLengths: "array",
    wrapPrivateKey: "boolean",
    isTorsionFree: "function",
    clearCofactor: "function",
    allowInfinityPoint: "boolean",
    fromBytes: "function",
    toBytes: "function"
  });
  const { endo, Fp, a } = opts;
  if (endo) {
    if (!Fp.eql(a, Fp.ZERO)) {
      throw new Error("invalid endomorphism, can only be defined for Koblitz curves that have a=0");
    }
    if (typeof endo !== "object" || typeof endo.beta !== "bigint" || typeof endo.splitScalar !== "function") {
      throw new Error("invalid endomorphism, expected beta: bigint and splitScalar: function");
    }
  }
  return Object.freeze({ ...opts });
}
var { bytesToNumberBE: b2n, hexToBytes: h2b } = exports_utils;

class DERErr extends Error {
  constructor(m = "") {
    super(m);
  }
}
var DER = {
  Err: DERErr,
  _tlv: {
    encode: (tag, data) => {
      const { Err: E } = DER;
      if (tag < 0 || tag > 256)
        throw new E("tlv.encode: wrong tag");
      if (data.length & 1)
        throw new E("tlv.encode: unpadded data");
      const dataLen = data.length / 2;
      const len = numberToHexUnpadded(dataLen);
      if (len.length / 2 & 128)
        throw new E("tlv.encode: long form length too big");
      const lenLen = dataLen > 127 ? numberToHexUnpadded(len.length / 2 | 128) : "";
      const t = numberToHexUnpadded(tag);
      return t + lenLen + len + data;
    },
    decode(tag, data) {
      const { Err: E } = DER;
      let pos = 0;
      if (tag < 0 || tag > 256)
        throw new E("tlv.encode: wrong tag");
      if (data.length < 2 || data[pos++] !== tag)
        throw new E("tlv.decode: wrong tlv");
      const first = data[pos++];
      const isLong = !!(first & 128);
      let length = 0;
      if (!isLong)
        length = first;
      else {
        const lenLen = first & 127;
        if (!lenLen)
          throw new E("tlv.decode(long): indefinite length not supported");
        if (lenLen > 4)
          throw new E("tlv.decode(long): byte length is too big");
        const lengthBytes = data.subarray(pos, pos + lenLen);
        if (lengthBytes.length !== lenLen)
          throw new E("tlv.decode: length bytes not complete");
        if (lengthBytes[0] === 0)
          throw new E("tlv.decode(long): zero leftmost byte");
        for (const b of lengthBytes)
          length = length << 8 | b;
        pos += lenLen;
        if (length < 128)
          throw new E("tlv.decode(long): not minimal encoding");
      }
      const v = data.subarray(pos, pos + length);
      if (v.length !== length)
        throw new E("tlv.decode: wrong value length");
      return { v, l: data.subarray(pos + length) };
    }
  },
  _int: {
    encode(num) {
      const { Err: E } = DER;
      if (num < _0n4)
        throw new E("integer: negative integers are not allowed");
      let hex = numberToHexUnpadded(num);
      if (Number.parseInt(hex[0], 16) & 8)
        hex = "00" + hex;
      if (hex.length & 1)
        throw new E("unexpected DER parsing assertion: unpadded hex");
      return hex;
    },
    decode(data) {
      const { Err: E } = DER;
      if (data[0] & 128)
        throw new E("invalid signature integer: negative");
      if (data[0] === 0 && !(data[1] & 128))
        throw new E("invalid signature integer: unnecessary leading zero");
      return b2n(data);
    }
  },
  toSig(hex) {
    const { Err: E, _int: int, _tlv: tlv } = DER;
    const data = typeof hex === "string" ? h2b(hex) : hex;
    abytes2(data);
    const { v: seqBytes, l: seqLeftBytes } = tlv.decode(48, data);
    if (seqLeftBytes.length)
      throw new E("invalid signature: left bytes after parsing");
    const { v: rBytes, l: rLeftBytes } = tlv.decode(2, seqBytes);
    const { v: sBytes, l: sLeftBytes } = tlv.decode(2, rLeftBytes);
    if (sLeftBytes.length)
      throw new E("invalid signature: left bytes after parsing");
    return { r: int.decode(rBytes), s: int.decode(sBytes) };
  },
  hexFromSig(sig) {
    const { _tlv: tlv, _int: int } = DER;
    const rs = tlv.encode(2, int.encode(sig.r));
    const ss = tlv.encode(2, int.encode(sig.s));
    const seq = rs + ss;
    return tlv.encode(48, seq);
  }
};
var _0n4 = BigInt(0);
var _1n4 = BigInt(1);
var _2n3 = BigInt(2);
var _3n2 = BigInt(3);
var _4n2 = BigInt(4);
function weierstrassPoints(opts) {
  const CURVE = validatePointOpts(opts);
  const { Fp } = CURVE;
  const Fn = Field(CURVE.n, CURVE.nBitLength);
  const toBytes2 = CURVE.toBytes || ((_c, point, _isCompressed) => {
    const a = point.toAffine();
    return concatBytes2(Uint8Array.from([4]), Fp.toBytes(a.x), Fp.toBytes(a.y));
  });
  const fromBytes = CURVE.fromBytes || ((bytes) => {
    const tail = bytes.subarray(1);
    const x = Fp.fromBytes(tail.subarray(0, Fp.BYTES));
    const y = Fp.fromBytes(tail.subarray(Fp.BYTES, 2 * Fp.BYTES));
    return { x, y };
  });
  function weierstrassEquation(x) {
    const { a, b } = CURVE;
    const x2 = Fp.sqr(x);
    const x3 = Fp.mul(x2, x);
    return Fp.add(Fp.add(x3, Fp.mul(x, a)), b);
  }
  if (!Fp.eql(Fp.sqr(CURVE.Gy), weierstrassEquation(CURVE.Gx)))
    throw new Error("bad generator point: equation left != right");
  function isWithinCurveOrder(num) {
    return inRange(num, _1n4, CURVE.n);
  }
  function normPrivateKeyToScalar(key) {
    const { allowedPrivateKeyLengths: lengths, nByteLength, wrapPrivateKey, n: N } = CURVE;
    if (lengths && typeof key !== "bigint") {
      if (isBytes2(key))
        key = bytesToHex(key);
      if (typeof key !== "string" || !lengths.includes(key.length))
        throw new Error("invalid private key");
      key = key.padStart(nByteLength * 2, "0");
    }
    let num;
    try {
      num = typeof key === "bigint" ? key : bytesToNumberBE(ensureBytes("private key", key, nByteLength));
    } catch (error) {
      throw new Error("invalid private key, expected hex or " + nByteLength + " bytes, got " + typeof key);
    }
    if (wrapPrivateKey)
      num = mod(num, N);
    aInRange("private key", num, _1n4, N);
    return num;
  }
  function assertPrjPoint(other) {
    if (!(other instanceof Point))
      throw new Error("ProjectivePoint expected");
  }
  const toAffineMemo = memoized((p, iz) => {
    const { px: x, py: y, pz: z } = p;
    if (Fp.eql(z, Fp.ONE))
      return { x, y };
    const is0 = p.is0();
    if (iz == null)
      iz = is0 ? Fp.ONE : Fp.inv(z);
    const ax = Fp.mul(x, iz);
    const ay = Fp.mul(y, iz);
    const zz = Fp.mul(z, iz);
    if (is0)
      return { x: Fp.ZERO, y: Fp.ZERO };
    if (!Fp.eql(zz, Fp.ONE))
      throw new Error("invZ was invalid");
    return { x: ax, y: ay };
  });
  const assertValidMemo = memoized((p) => {
    if (p.is0()) {
      if (CURVE.allowInfinityPoint && !Fp.is0(p.py))
        return;
      throw new Error("bad point: ZERO");
    }
    const { x, y } = p.toAffine();
    if (!Fp.isValid(x) || !Fp.isValid(y))
      throw new Error("bad point: x or y not FE");
    const left = Fp.sqr(y);
    const right = weierstrassEquation(x);
    if (!Fp.eql(left, right))
      throw new Error("bad point: equation left != right");
    if (!p.isTorsionFree())
      throw new Error("bad point: not in prime-order subgroup");
    return true;
  });

  class Point {
    constructor(px, py, pz) {
      this.px = px;
      this.py = py;
      this.pz = pz;
      if (px == null || !Fp.isValid(px))
        throw new Error("x required");
      if (py == null || !Fp.isValid(py))
        throw new Error("y required");
      if (pz == null || !Fp.isValid(pz))
        throw new Error("z required");
      Object.freeze(this);
    }
    static fromAffine(p) {
      const { x, y } = p || {};
      if (!p || !Fp.isValid(x) || !Fp.isValid(y))
        throw new Error("invalid affine point");
      if (p instanceof Point)
        throw new Error("projective point not allowed");
      const is0 = (i) => Fp.eql(i, Fp.ZERO);
      if (is0(x) && is0(y))
        return Point.ZERO;
      return new Point(x, y, Fp.ONE);
    }
    get x() {
      return this.toAffine().x;
    }
    get y() {
      return this.toAffine().y;
    }
    static normalizeZ(points) {
      const toInv = Fp.invertBatch(points.map((p) => p.pz));
      return points.map((p, i) => p.toAffine(toInv[i])).map(Point.fromAffine);
    }
    static fromHex(hex) {
      const P = Point.fromAffine(fromBytes(ensureBytes("pointHex", hex)));
      P.assertValidity();
      return P;
    }
    static fromPrivateKey(privateKey) {
      return Point.BASE.multiply(normPrivateKeyToScalar(privateKey));
    }
    static msm(points, scalars) {
      return pippenger(Point, Fn, points, scalars);
    }
    _setWindowSize(windowSize) {
      wnaf.setWindowSize(this, windowSize);
    }
    assertValidity() {
      assertValidMemo(this);
    }
    hasEvenY() {
      const { y } = this.toAffine();
      if (Fp.isOdd)
        return !Fp.isOdd(y);
      throw new Error("Field doesn't support isOdd");
    }
    equals(other) {
      assertPrjPoint(other);
      const { px: X1, py: Y1, pz: Z1 } = this;
      const { px: X2, py: Y2, pz: Z2 } = other;
      const U1 = Fp.eql(Fp.mul(X1, Z2), Fp.mul(X2, Z1));
      const U2 = Fp.eql(Fp.mul(Y1, Z2), Fp.mul(Y2, Z1));
      return U1 && U2;
    }
    negate() {
      return new Point(this.px, Fp.neg(this.py), this.pz);
    }
    double() {
      const { a, b } = CURVE;
      const b3 = Fp.mul(b, _3n2);
      const { px: X1, py: Y1, pz: Z1 } = this;
      let { ZERO: X3, ZERO: Y3, ZERO: Z3 } = Fp;
      let t0 = Fp.mul(X1, X1);
      let t1 = Fp.mul(Y1, Y1);
      let t2 = Fp.mul(Z1, Z1);
      let t3 = Fp.mul(X1, Y1);
      t3 = Fp.add(t3, t3);
      Z3 = Fp.mul(X1, Z1);
      Z3 = Fp.add(Z3, Z3);
      X3 = Fp.mul(a, Z3);
      Y3 = Fp.mul(b3, t2);
      Y3 = Fp.add(X3, Y3);
      X3 = Fp.sub(t1, Y3);
      Y3 = Fp.add(t1, Y3);
      Y3 = Fp.mul(X3, Y3);
      X3 = Fp.mul(t3, X3);
      Z3 = Fp.mul(b3, Z3);
      t2 = Fp.mul(a, t2);
      t3 = Fp.sub(t0, t2);
      t3 = Fp.mul(a, t3);
      t3 = Fp.add(t3, Z3);
      Z3 = Fp.add(t0, t0);
      t0 = Fp.add(Z3, t0);
      t0 = Fp.add(t0, t2);
      t0 = Fp.mul(t0, t3);
      Y3 = Fp.add(Y3, t0);
      t2 = Fp.mul(Y1, Z1);
      t2 = Fp.add(t2, t2);
      t0 = Fp.mul(t2, t3);
      X3 = Fp.sub(X3, t0);
      Z3 = Fp.mul(t2, t1);
      Z3 = Fp.add(Z3, Z3);
      Z3 = Fp.add(Z3, Z3);
      return new Point(X3, Y3, Z3);
    }
    add(other) {
      assertPrjPoint(other);
      const { px: X1, py: Y1, pz: Z1 } = this;
      const { px: X2, py: Y2, pz: Z2 } = other;
      let { ZERO: X3, ZERO: Y3, ZERO: Z3 } = Fp;
      const a = CURVE.a;
      const b3 = Fp.mul(CURVE.b, _3n2);
      let t0 = Fp.mul(X1, X2);
      let t1 = Fp.mul(Y1, Y2);
      let t2 = Fp.mul(Z1, Z2);
      let t3 = Fp.add(X1, Y1);
      let t4 = Fp.add(X2, Y2);
      t3 = Fp.mul(t3, t4);
      t4 = Fp.add(t0, t1);
      t3 = Fp.sub(t3, t4);
      t4 = Fp.add(X1, Z1);
      let t5 = Fp.add(X2, Z2);
      t4 = Fp.mul(t4, t5);
      t5 = Fp.add(t0, t2);
      t4 = Fp.sub(t4, t5);
      t5 = Fp.add(Y1, Z1);
      X3 = Fp.add(Y2, Z2);
      t5 = Fp.mul(t5, X3);
      X3 = Fp.add(t1, t2);
      t5 = Fp.sub(t5, X3);
      Z3 = Fp.mul(a, t4);
      X3 = Fp.mul(b3, t2);
      Z3 = Fp.add(X3, Z3);
      X3 = Fp.sub(t1, Z3);
      Z3 = Fp.add(t1, Z3);
      Y3 = Fp.mul(X3, Z3);
      t1 = Fp.add(t0, t0);
      t1 = Fp.add(t1, t0);
      t2 = Fp.mul(a, t2);
      t4 = Fp.mul(b3, t4);
      t1 = Fp.add(t1, t2);
      t2 = Fp.sub(t0, t2);
      t2 = Fp.mul(a, t2);
      t4 = Fp.add(t4, t2);
      t0 = Fp.mul(t1, t4);
      Y3 = Fp.add(Y3, t0);
      t0 = Fp.mul(t5, t4);
      X3 = Fp.mul(t3, X3);
      X3 = Fp.sub(X3, t0);
      t0 = Fp.mul(t3, t1);
      Z3 = Fp.mul(t5, Z3);
      Z3 = Fp.add(Z3, t0);
      return new Point(X3, Y3, Z3);
    }
    subtract(other) {
      return this.add(other.negate());
    }
    is0() {
      return this.equals(Point.ZERO);
    }
    wNAF(n) {
      return wnaf.wNAFCached(this, n, Point.normalizeZ);
    }
    multiplyUnsafe(sc) {
      const { endo, n: N } = CURVE;
      aInRange("scalar", sc, _0n4, N);
      const I = Point.ZERO;
      if (sc === _0n4)
        return I;
      if (this.is0() || sc === _1n4)
        return this;
      if (!endo || wnaf.hasPrecomputes(this))
        return wnaf.wNAFCachedUnsafe(this, sc, Point.normalizeZ);
      let { k1neg, k1, k2neg, k2 } = endo.splitScalar(sc);
      let k1p = I;
      let k2p = I;
      let d = this;
      while (k1 > _0n4 || k2 > _0n4) {
        if (k1 & _1n4)
          k1p = k1p.add(d);
        if (k2 & _1n4)
          k2p = k2p.add(d);
        d = d.double();
        k1 >>= _1n4;
        k2 >>= _1n4;
      }
      if (k1neg)
        k1p = k1p.negate();
      if (k2neg)
        k2p = k2p.negate();
      k2p = new Point(Fp.mul(k2p.px, endo.beta), k2p.py, k2p.pz);
      return k1p.add(k2p);
    }
    multiply(scalar) {
      const { endo, n: N } = CURVE;
      aInRange("scalar", scalar, _1n4, N);
      let point, fake;
      if (endo) {
        const { k1neg, k1, k2neg, k2 } = endo.splitScalar(scalar);
        let { p: k1p, f: f1p } = this.wNAF(k1);
        let { p: k2p, f: f2p } = this.wNAF(k2);
        k1p = wnaf.constTimeNegate(k1neg, k1p);
        k2p = wnaf.constTimeNegate(k2neg, k2p);
        k2p = new Point(Fp.mul(k2p.px, endo.beta), k2p.py, k2p.pz);
        point = k1p.add(k2p);
        fake = f1p.add(f2p);
      } else {
        const { p, f } = this.wNAF(scalar);
        point = p;
        fake = f;
      }
      return Point.normalizeZ([point, fake])[0];
    }
    multiplyAndAddUnsafe(Q, a, b) {
      const G = Point.BASE;
      const mul = (P, a2) => a2 === _0n4 || a2 === _1n4 || !P.equals(G) ? P.multiplyUnsafe(a2) : P.multiply(a2);
      const sum = mul(this, a).add(mul(Q, b));
      return sum.is0() ? undefined : sum;
    }
    toAffine(iz) {
      return toAffineMemo(this, iz);
    }
    isTorsionFree() {
      const { h: cofactor, isTorsionFree } = CURVE;
      if (cofactor === _1n4)
        return true;
      if (isTorsionFree)
        return isTorsionFree(Point, this);
      throw new Error("isTorsionFree() has not been declared for the elliptic curve");
    }
    clearCofactor() {
      const { h: cofactor, clearCofactor } = CURVE;
      if (cofactor === _1n4)
        return this;
      if (clearCofactor)
        return clearCofactor(Point, this);
      return this.multiplyUnsafe(CURVE.h);
    }
    toRawBytes(isCompressed = true) {
      abool("isCompressed", isCompressed);
      this.assertValidity();
      return toBytes2(Point, this, isCompressed);
    }
    toHex(isCompressed = true) {
      abool("isCompressed", isCompressed);
      return bytesToHex(this.toRawBytes(isCompressed));
    }
  }
  Point.BASE = new Point(CURVE.Gx, CURVE.Gy, Fp.ONE);
  Point.ZERO = new Point(Fp.ZERO, Fp.ONE, Fp.ZERO);
  const _bits = CURVE.nBitLength;
  const wnaf = wNAF(Point, CURVE.endo ? Math.ceil(_bits / 2) : _bits);
  return {
    CURVE,
    ProjectivePoint: Point,
    normPrivateKeyToScalar,
    weierstrassEquation,
    isWithinCurveOrder
  };
}
function validateOpts(curve) {
  const opts = validateBasic(curve);
  validateObject(opts, {
    hash: "hash",
    hmac: "function",
    randomBytes: "function"
  }, {
    bits2int: "function",
    bits2int_modN: "function",
    lowS: "boolean"
  });
  return Object.freeze({ lowS: true, ...opts });
}
function weierstrass(curveDef) {
  const CURVE = validateOpts(curveDef);
  const { Fp, n: CURVE_ORDER } = CURVE;
  const compressedLen = Fp.BYTES + 1;
  const uncompressedLen = 2 * Fp.BYTES + 1;
  function modN(a) {
    return mod(a, CURVE_ORDER);
  }
  function invN(a) {
    return invert(a, CURVE_ORDER);
  }
  const { ProjectivePoint: Point, normPrivateKeyToScalar, weierstrassEquation, isWithinCurveOrder } = weierstrassPoints({
    ...CURVE,
    toBytes(_c, point, isCompressed) {
      const a = point.toAffine();
      const x = Fp.toBytes(a.x);
      const cat = concatBytes2;
      abool("isCompressed", isCompressed);
      if (isCompressed) {
        return cat(Uint8Array.from([point.hasEvenY() ? 2 : 3]), x);
      } else {
        return cat(Uint8Array.from([4]), x, Fp.toBytes(a.y));
      }
    },
    fromBytes(bytes) {
      const len = bytes.length;
      const head = bytes[0];
      const tail = bytes.subarray(1);
      if (len === compressedLen && (head === 2 || head === 3)) {
        const x = bytesToNumberBE(tail);
        if (!inRange(x, _1n4, Fp.ORDER))
          throw new Error("Point is not on curve");
        const y2 = weierstrassEquation(x);
        let y;
        try {
          y = Fp.sqrt(y2);
        } catch (sqrtError) {
          const suffix = sqrtError instanceof Error ? ": " + sqrtError.message : "";
          throw new Error("Point is not on curve" + suffix);
        }
        const isYOdd = (y & _1n4) === _1n4;
        const isHeadOdd = (head & 1) === 1;
        if (isHeadOdd !== isYOdd)
          y = Fp.neg(y);
        return { x, y };
      } else if (len === uncompressedLen && head === 4) {
        const x = Fp.fromBytes(tail.subarray(0, Fp.BYTES));
        const y = Fp.fromBytes(tail.subarray(Fp.BYTES, 2 * Fp.BYTES));
        return { x, y };
      } else {
        const cl = compressedLen;
        const ul = uncompressedLen;
        throw new Error("invalid Point, expected length of " + cl + ", or uncompressed " + ul + ", got " + len);
      }
    }
  });
  const numToNByteStr = (num) => bytesToHex(numberToBytesBE(num, CURVE.nByteLength));
  function isBiggerThanHalfOrder(number) {
    const HALF = CURVE_ORDER >> _1n4;
    return number > HALF;
  }
  function normalizeS(s) {
    return isBiggerThanHalfOrder(s) ? modN(-s) : s;
  }
  const slcNum = (b, from, to) => bytesToNumberBE(b.slice(from, to));

  class Signature {
    constructor(r, s, recovery) {
      this.r = r;
      this.s = s;
      this.recovery = recovery;
      this.assertValidity();
    }
    static fromCompact(hex) {
      const l = CURVE.nByteLength;
      hex = ensureBytes("compactSignature", hex, l * 2);
      return new Signature(slcNum(hex, 0, l), slcNum(hex, l, 2 * l));
    }
    static fromDER(hex) {
      const { r, s } = DER.toSig(ensureBytes("DER", hex));
      return new Signature(r, s);
    }
    assertValidity() {
      aInRange("r", this.r, _1n4, CURVE_ORDER);
      aInRange("s", this.s, _1n4, CURVE_ORDER);
    }
    addRecoveryBit(recovery) {
      return new Signature(this.r, this.s, recovery);
    }
    recoverPublicKey(msgHash) {
      const { r, s, recovery: rec } = this;
      const h = bits2int_modN(ensureBytes("msgHash", msgHash));
      if (rec == null || ![0, 1, 2, 3].includes(rec))
        throw new Error("recovery id invalid");
      const radj = rec === 2 || rec === 3 ? r + CURVE.n : r;
      if (radj >= Fp.ORDER)
        throw new Error("recovery id 2 or 3 invalid");
      const prefix = (rec & 1) === 0 ? "02" : "03";
      const R = Point.fromHex(prefix + numToNByteStr(radj));
      const ir = invN(radj);
      const u1 = modN(-h * ir);
      const u2 = modN(s * ir);
      const Q = Point.BASE.multiplyAndAddUnsafe(R, u1, u2);
      if (!Q)
        throw new Error("point at infinify");
      Q.assertValidity();
      return Q;
    }
    hasHighS() {
      return isBiggerThanHalfOrder(this.s);
    }
    normalizeS() {
      return this.hasHighS() ? new Signature(this.r, modN(-this.s), this.recovery) : this;
    }
    toDERRawBytes() {
      return hexToBytes(this.toDERHex());
    }
    toDERHex() {
      return DER.hexFromSig({ r: this.r, s: this.s });
    }
    toCompactRawBytes() {
      return hexToBytes(this.toCompactHex());
    }
    toCompactHex() {
      return numToNByteStr(this.r) + numToNByteStr(this.s);
    }
  }
  const utils = {
    isValidPrivateKey(privateKey) {
      try {
        normPrivateKeyToScalar(privateKey);
        return true;
      } catch (error) {
        return false;
      }
    },
    normPrivateKeyToScalar,
    randomPrivateKey: () => {
      const length = getMinHashLength(CURVE.n);
      return mapHashToField(CURVE.randomBytes(length), CURVE.n);
    },
    precompute(windowSize = 8, point = Point.BASE) {
      point._setWindowSize(windowSize);
      point.multiply(BigInt(3));
      return point;
    }
  };
  function getPublicKey(privateKey, isCompressed = true) {
    return Point.fromPrivateKey(privateKey).toRawBytes(isCompressed);
  }
  function isProbPub(item) {
    const arr = isBytes2(item);
    const str = typeof item === "string";
    const len = (arr || str) && item.length;
    if (arr)
      return len === compressedLen || len === uncompressedLen;
    if (str)
      return len === 2 * compressedLen || len === 2 * uncompressedLen;
    if (item instanceof Point)
      return true;
    return false;
  }
  function getSharedSecret(privateA, publicB, isCompressed = true) {
    if (isProbPub(privateA))
      throw new Error("first arg must be private key");
    if (!isProbPub(publicB))
      throw new Error("second arg must be public key");
    const b = Point.fromHex(publicB);
    return b.multiply(normPrivateKeyToScalar(privateA)).toRawBytes(isCompressed);
  }
  const bits2int = CURVE.bits2int || function(bytes) {
    if (bytes.length > 8192)
      throw new Error("input is too large");
    const num = bytesToNumberBE(bytes);
    const delta = bytes.length * 8 - CURVE.nBitLength;
    return delta > 0 ? num >> BigInt(delta) : num;
  };
  const bits2int_modN = CURVE.bits2int_modN || function(bytes) {
    return modN(bits2int(bytes));
  };
  const ORDER_MASK = bitMask(CURVE.nBitLength);
  function int2octets(num) {
    aInRange("num < 2^" + CURVE.nBitLength, num, _0n4, ORDER_MASK);
    return numberToBytesBE(num, CURVE.nByteLength);
  }
  function prepSig(msgHash, privateKey, opts = defaultSigOpts) {
    if (["recovered", "canonical"].some((k) => (k in opts)))
      throw new Error("sign() legacy options not supported");
    const { hash, randomBytes: randomBytes2 } = CURVE;
    let { lowS, prehash, extraEntropy: ent } = opts;
    if (lowS == null)
      lowS = true;
    msgHash = ensureBytes("msgHash", msgHash);
    validateSigVerOpts(opts);
    if (prehash)
      msgHash = ensureBytes("prehashed msgHash", hash(msgHash));
    const h1int = bits2int_modN(msgHash);
    const d = normPrivateKeyToScalar(privateKey);
    const seedArgs = [int2octets(d), int2octets(h1int)];
    if (ent != null && ent !== false) {
      const e = ent === true ? randomBytes2(Fp.BYTES) : ent;
      seedArgs.push(ensureBytes("extraEntropy", e));
    }
    const seed = concatBytes2(...seedArgs);
    const m = h1int;
    function k2sig(kBytes) {
      const k = bits2int(kBytes);
      if (!isWithinCurveOrder(k))
        return;
      const ik = invN(k);
      const q = Point.BASE.multiply(k).toAffine();
      const r = modN(q.x);
      if (r === _0n4)
        return;
      const s = modN(ik * modN(m + r * d));
      if (s === _0n4)
        return;
      let recovery = (q.x === r ? 0 : 2) | Number(q.y & _1n4);
      let normS = s;
      if (lowS && isBiggerThanHalfOrder(s)) {
        normS = normalizeS(s);
        recovery ^= 1;
      }
      return new Signature(r, normS, recovery);
    }
    return { seed, k2sig };
  }
  const defaultSigOpts = { lowS: CURVE.lowS, prehash: false };
  const defaultVerOpts = { lowS: CURVE.lowS, prehash: false };
  function sign(msgHash, privKey, opts = defaultSigOpts) {
    const { seed, k2sig } = prepSig(msgHash, privKey, opts);
    const C = CURVE;
    const drbg = createHmacDrbg(C.hash.outputLen, C.nByteLength, C.hmac);
    return drbg(seed, k2sig);
  }
  Point.BASE._setWindowSize(8);
  function verify(signature, msgHash, publicKey, opts = defaultVerOpts) {
    const sg = signature;
    msgHash = ensureBytes("msgHash", msgHash);
    publicKey = ensureBytes("publicKey", publicKey);
    const { lowS, prehash, format } = opts;
    validateSigVerOpts(opts);
    if ("strict" in opts)
      throw new Error("options.strict was renamed to lowS");
    if (format !== undefined && format !== "compact" && format !== "der")
      throw new Error("format must be compact or der");
    const isHex = typeof sg === "string" || isBytes2(sg);
    const isObj = !isHex && !format && typeof sg === "object" && sg !== null && typeof sg.r === "bigint" && typeof sg.s === "bigint";
    if (!isHex && !isObj)
      throw new Error("invalid signature, expected Uint8Array, hex string or Signature instance");
    let _sig = undefined;
    let P;
    try {
      if (isObj)
        _sig = new Signature(sg.r, sg.s);
      if (isHex) {
        try {
          if (format !== "compact")
            _sig = Signature.fromDER(sg);
        } catch (derError) {
          if (!(derError instanceof DER.Err))
            throw derError;
        }
        if (!_sig && format !== "der")
          _sig = Signature.fromCompact(sg);
      }
      P = Point.fromHex(publicKey);
    } catch (error) {
      return false;
    }
    if (!_sig)
      return false;
    if (lowS && _sig.hasHighS())
      return false;
    if (prehash)
      msgHash = CURVE.hash(msgHash);
    const { r, s } = _sig;
    const h = bits2int_modN(msgHash);
    const is = invN(s);
    const u1 = modN(h * is);
    const u2 = modN(r * is);
    const R = Point.BASE.multiplyAndAddUnsafe(P, u1, u2)?.toAffine();
    if (!R)
      return false;
    const v = modN(R.x);
    return v === r;
  }
  return {
    CURVE,
    getPublicKey,
    getSharedSecret,
    sign,
    verify,
    ProjectivePoint: Point,
    Signature,
    utils
  };
}

// node_modules/@noble/curves/esm/_shortw_utils.js
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
function getHash(hash) {
  return {
    hash,
    hmac: (key, ...msgs) => hmac(hash, key, concatBytes(...msgs)),
    randomBytes
  };
}
function createCurve(curveDef, defHash) {
  const create = (hash) => weierstrass({ ...curveDef, ...getHash(hash) });
  return { ...create(defHash), create };
}

// node_modules/@noble/curves/esm/secp256k1.js
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
var secp256k1P = BigInt("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
var secp256k1N = BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
var _1n5 = BigInt(1);
var _2n4 = BigInt(2);
var divNearest = (a, b) => (a + b / _2n4) / b;
function sqrtMod(y) {
  const P = secp256k1P;
  const _3n3 = BigInt(3), _6n = BigInt(6), _11n = BigInt(11), _22n = BigInt(22);
  const _23n = BigInt(23), _44n = BigInt(44), _88n = BigInt(88);
  const b2 = y * y * y % P;
  const b3 = b2 * b2 * y % P;
  const b6 = pow2(b3, _3n3, P) * b3 % P;
  const b9 = pow2(b6, _3n3, P) * b3 % P;
  const b11 = pow2(b9, _2n4, P) * b2 % P;
  const b22 = pow2(b11, _11n, P) * b11 % P;
  const b44 = pow2(b22, _22n, P) * b22 % P;
  const b88 = pow2(b44, _44n, P) * b44 % P;
  const b176 = pow2(b88, _88n, P) * b88 % P;
  const b220 = pow2(b176, _44n, P) * b44 % P;
  const b223 = pow2(b220, _3n3, P) * b3 % P;
  const t1 = pow2(b223, _23n, P) * b22 % P;
  const t2 = pow2(t1, _6n, P) * b2 % P;
  const root = pow2(t2, _2n4, P);
  if (!Fpk1.eql(Fpk1.sqr(root), y))
    throw new Error("Cannot find square root");
  return root;
}
var Fpk1 = Field(secp256k1P, undefined, undefined, { sqrt: sqrtMod });
var secp256k1 = createCurve({
  a: BigInt(0),
  b: BigInt(7),
  Fp: Fpk1,
  n: secp256k1N,
  Gx: BigInt("55066263022277343669578718895168534326250603453777594175500187360389116729240"),
  Gy: BigInt("32670510020758816978083085130507043184471273380659243275938904335757337482424"),
  h: BigInt(1),
  lowS: true,
  endo: {
    beta: BigInt("0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee"),
    splitScalar: (k) => {
      const n = secp256k1N;
      const a1 = BigInt("0x3086d221a7d46bcde86c90e49284eb15");
      const b1 = -_1n5 * BigInt("0xe4437ed6010e88286f547fa90abfe4c3");
      const a2 = BigInt("0x114ca50f7a8e2f3f657c1108d9d44cfd8");
      const b2 = a1;
      const POW_2_128 = BigInt("0x100000000000000000000000000000000");
      const c1 = divNearest(b2 * k, n);
      const c2 = divNearest(-b1 * k, n);
      let k1 = mod(k - c1 * a1 - c2 * a2, n);
      let k2 = mod(-c1 * b1 - c2 * b2, n);
      const k1neg = k1 > POW_2_128;
      const k2neg = k2 > POW_2_128;
      if (k1neg)
        k1 = n - k1;
      if (k2neg)
        k2 = n - k2;
      if (k1 > POW_2_128 || k2 > POW_2_128) {
        throw new Error("splitScalar: Endomorphism failed, k=" + k);
      }
      return { k1neg, k1, k2neg, k2 };
    }
  }
}, sha256);
var _0n5 = BigInt(0);
var TAGGED_HASH_PREFIXES = {};
function taggedHash(tag, ...messages) {
  let tagP = TAGGED_HASH_PREFIXES[tag];
  if (tagP === undefined) {
    const tagH = sha256(Uint8Array.from(tag, (c) => c.charCodeAt(0)));
    tagP = concatBytes2(tagH, tagH);
    TAGGED_HASH_PREFIXES[tag] = tagP;
  }
  return sha256(concatBytes2(tagP, ...messages));
}
var pointToBytes = (point) => point.toRawBytes(true).slice(1);
var numTo32b = (n) => numberToBytesBE(n, 32);
var modP = (x) => mod(x, secp256k1P);
var modN = (x) => mod(x, secp256k1N);
var Point = secp256k1.ProjectivePoint;
var GmulAdd = (Q, a, b) => Point.BASE.multiplyAndAddUnsafe(Q, a, b);
function schnorrGetExtPubKey(priv) {
  let d_ = secp256k1.utils.normPrivateKeyToScalar(priv);
  let p = Point.fromPrivateKey(d_);
  const scalar = p.hasEvenY() ? d_ : modN(-d_);
  return { scalar, bytes: pointToBytes(p) };
}
function lift_x(x) {
  aInRange("x", x, _1n5, secp256k1P);
  const xx = modP(x * x);
  const c = modP(xx * x + BigInt(7));
  let y = sqrtMod(c);
  if (y % _2n4 !== _0n5)
    y = modP(-y);
  const p = new Point(x, y, _1n5);
  p.assertValidity();
  return p;
}
var num = bytesToNumberBE;
function challenge(...args) {
  return modN(num(taggedHash("BIP0340/challenge", ...args)));
}
function schnorrGetPublicKey(privateKey) {
  return schnorrGetExtPubKey(privateKey).bytes;
}
function schnorrSign(message, privateKey, auxRand = randomBytes(32)) {
  const m = ensureBytes("message", message);
  const { bytes: px, scalar: d } = schnorrGetExtPubKey(privateKey);
  const a = ensureBytes("auxRand", auxRand, 32);
  const t = numTo32b(d ^ num(taggedHash("BIP0340/aux", a)));
  const rand = taggedHash("BIP0340/nonce", t, px, m);
  const k_ = modN(num(rand));
  if (k_ === _0n5)
    throw new Error("sign failed: k is zero");
  const { bytes: rx, scalar: k } = schnorrGetExtPubKey(k_);
  const e = challenge(rx, px, m);
  const sig = new Uint8Array(64);
  sig.set(rx, 0);
  sig.set(numTo32b(modN(k + e * d)), 32);
  if (!schnorrVerify(sig, m, px))
    throw new Error("sign: Invalid signature produced");
  return sig;
}
function schnorrVerify(signature, message, publicKey) {
  const sig = ensureBytes("signature", signature, 64);
  const m = ensureBytes("message", message);
  const pub = ensureBytes("publicKey", publicKey, 32);
  try {
    const P = lift_x(num(pub));
    const r = num(sig.subarray(0, 32));
    if (!inRange(r, _1n5, secp256k1P))
      return false;
    const s = num(sig.subarray(32, 64));
    if (!inRange(s, _1n5, secp256k1N))
      return false;
    const e = challenge(numTo32b(r), pointToBytes(P), m);
    const R = GmulAdd(P, s, modN(-e));
    if (!R || !R.hasEvenY() || R.toAffine().x !== r)
      return false;
    return true;
  } catch (error) {
    return false;
  }
}
var schnorr = /* @__PURE__ */ (() => ({
  getPublicKey: schnorrGetPublicKey,
  sign: schnorrSign,
  verify: schnorrVerify,
  utils: {
    randomPrivateKey: secp256k1.utils.randomPrivateKey,
    lift_x,
    pointToBytes,
    numberToBytesBE,
    bytesToNumberBE,
    taggedHash,
    mod
  }
}))();

// node_modules/@noble/hashes/esm/ripemd160.js
var Rho = /* @__PURE__ */ new Uint8Array([7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8]);
var Id = /* @__PURE__ */ new Uint8Array(new Array(16).fill(0).map((_, i) => i));
var Pi = /* @__PURE__ */ Id.map((i) => (9 * i + 5) % 16);
var idxL = [Id];
var idxR = [Pi];
for (let i = 0;i < 4; i++)
  for (let j of [idxL, idxR])
    j.push(j[i].map((k) => Rho[k]));
var shifts = /* @__PURE__ */ [
  [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
  [12, 13, 11, 15, 6, 9, 9, 7, 12, 15, 11, 13, 7, 8, 7, 7],
  [13, 15, 14, 11, 7, 7, 6, 8, 13, 14, 13, 12, 5, 5, 6, 9],
  [14, 11, 12, 14, 8, 6, 5, 5, 15, 12, 15, 14, 9, 9, 8, 6],
  [15, 12, 13, 13, 9, 5, 8, 6, 14, 11, 12, 11, 8, 6, 5, 5]
].map((i) => new Uint8Array(i));
var shiftsL = /* @__PURE__ */ idxL.map((idx, i) => idx.map((j) => shifts[i][j]));
var shiftsR = /* @__PURE__ */ idxR.map((idx, i) => idx.map((j) => shifts[i][j]));
var Kl = /* @__PURE__ */ new Uint32Array([
  0,
  1518500249,
  1859775393,
  2400959708,
  2840853838
]);
var Kr = /* @__PURE__ */ new Uint32Array([
  1352829926,
  1548603684,
  1836072691,
  2053994217,
  0
]);
function f(group, x, y, z) {
  if (group === 0)
    return x ^ y ^ z;
  else if (group === 1)
    return x & y | ~x & z;
  else if (group === 2)
    return (x | ~y) ^ z;
  else if (group === 3)
    return x & z | y & ~z;
  else
    return x ^ (y | ~z);
}
var R_BUF = /* @__PURE__ */ new Uint32Array(16);

class RIPEMD160 extends HashMD {
  constructor() {
    super(64, 20, 8, true);
    this.h0 = 1732584193 | 0;
    this.h1 = 4023233417 | 0;
    this.h2 = 2562383102 | 0;
    this.h3 = 271733878 | 0;
    this.h4 = 3285377520 | 0;
  }
  get() {
    const { h0, h1, h2, h3, h4 } = this;
    return [h0, h1, h2, h3, h4];
  }
  set(h0, h1, h2, h3, h4) {
    this.h0 = h0 | 0;
    this.h1 = h1 | 0;
    this.h2 = h2 | 0;
    this.h3 = h3 | 0;
    this.h4 = h4 | 0;
  }
  process(view, offset) {
    for (let i = 0;i < 16; i++, offset += 4)
      R_BUF[i] = view.getUint32(offset, true);
    let al = this.h0 | 0, ar = al, bl = this.h1 | 0, br = bl, cl = this.h2 | 0, cr = cl, dl = this.h3 | 0, dr = dl, el = this.h4 | 0, er = el;
    for (let group = 0;group < 5; group++) {
      const rGroup = 4 - group;
      const hbl = Kl[group], hbr = Kr[group];
      const rl = idxL[group], rr = idxR[group];
      const sl = shiftsL[group], sr = shiftsR[group];
      for (let i = 0;i < 16; i++) {
        const tl = rotl(al + f(group, bl, cl, dl) + R_BUF[rl[i]] + hbl, sl[i]) + el | 0;
        al = el, el = dl, dl = rotl(cl, 10) | 0, cl = bl, bl = tl;
      }
      for (let i = 0;i < 16; i++) {
        const tr = rotl(ar + f(rGroup, br, cr, dr) + R_BUF[rr[i]] + hbr, sr[i]) + er | 0;
        ar = er, er = dr, dr = rotl(cr, 10) | 0, cr = br, br = tr;
      }
    }
    this.set(this.h1 + cl + dr | 0, this.h2 + dl + er | 0, this.h3 + el + ar | 0, this.h4 + al + br | 0, this.h0 + bl + cr | 0);
  }
  roundClean() {
    R_BUF.fill(0);
  }
  destroy() {
    this.destroyed = true;
    this.buffer.fill(0);
    this.set(0, 0, 0, 0, 0);
  }
}
var ripemd160 = /* @__PURE__ */ wrapConstructor(() => new RIPEMD160);

// node_modules/@scure/base/lib/esm/index.js
/*! scure-base - MIT License (c) 2022 Paul Miller (paulmillr.com) */
function isBytes3(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
}
function abytes3(b, ...lengths) {
  if (!isBytes3(b))
    throw new Error("Uint8Array expected");
  if (lengths.length > 0 && !lengths.includes(b.length))
    throw new Error("Uint8Array expected of length " + lengths + ", got length=" + b.length);
}
function isArrayOf(isString, arr) {
  if (!Array.isArray(arr))
    return false;
  if (arr.length === 0)
    return true;
  if (isString) {
    return arr.every((item) => typeof item === "string");
  } else {
    return arr.every((item) => Number.isSafeInteger(item));
  }
}
function afn(input) {
  if (typeof input !== "function")
    throw new Error("function expected");
  return true;
}
function astr(label, input) {
  if (typeof input !== "string")
    throw new Error(`${label}: string expected`);
  return true;
}
function anumber2(n) {
  if (!Number.isSafeInteger(n))
    throw new Error(`invalid integer: ${n}`);
}
function aArr(input) {
  if (!Array.isArray(input))
    throw new Error("array expected");
}
function astrArr(label, input) {
  if (!isArrayOf(true, input))
    throw new Error(`${label}: array of strings expected`);
}
function anumArr(label, input) {
  if (!isArrayOf(false, input))
    throw new Error(`${label}: array of numbers expected`);
}
function chain(...args) {
  const id = (a) => a;
  const wrap = (a, b) => (c) => a(b(c));
  const encode = args.map((x) => x.encode).reduceRight(wrap, id);
  const decode = args.map((x) => x.decode).reduce(wrap, id);
  return { encode, decode };
}
function alphabet(letters) {
  const lettersA = typeof letters === "string" ? letters.split("") : letters;
  const len = lettersA.length;
  astrArr("alphabet", lettersA);
  const indexes = new Map(lettersA.map((l, i) => [l, i]));
  return {
    encode: (digits) => {
      aArr(digits);
      return digits.map((i) => {
        if (!Number.isSafeInteger(i) || i < 0 || i >= len)
          throw new Error(`alphabet.encode: digit index outside alphabet "${i}". Allowed: ${letters}`);
        return lettersA[i];
      });
    },
    decode: (input) => {
      aArr(input);
      return input.map((letter) => {
        astr("alphabet.decode", letter);
        const i = indexes.get(letter);
        if (i === undefined)
          throw new Error(`Unknown letter: "${letter}". Allowed: ${letters}`);
        return i;
      });
    }
  };
}
function join(separator = "") {
  astr("join", separator);
  return {
    encode: (from) => {
      astrArr("join.decode", from);
      return from.join(separator);
    },
    decode: (to) => {
      astr("join.decode", to);
      return to.split(separator);
    }
  };
}
function padding(bits, chr = "=") {
  anumber2(bits);
  astr("padding", chr);
  return {
    encode(data) {
      astrArr("padding.encode", data);
      while (data.length * bits % 8)
        data.push(chr);
      return data;
    },
    decode(input) {
      astrArr("padding.decode", input);
      let end = input.length;
      if (end * bits % 8)
        throw new Error("padding: invalid, string should have whole number of bytes");
      for (;end > 0 && input[end - 1] === chr; end--) {
        const last = end - 1;
        const byte = last * bits;
        if (byte % 8 === 0)
          throw new Error("padding: invalid, string has too much padding");
      }
      return input.slice(0, end);
    }
  };
}
function normalize(fn) {
  afn(fn);
  return { encode: (from) => from, decode: (to) => fn(to) };
}
function convertRadix(data, from, to) {
  if (from < 2)
    throw new Error(`convertRadix: invalid from=${from}, base cannot be less than 2`);
  if (to < 2)
    throw new Error(`convertRadix: invalid to=${to}, base cannot be less than 2`);
  aArr(data);
  if (!data.length)
    return [];
  let pos = 0;
  const res = [];
  const digits = Array.from(data, (d) => {
    anumber2(d);
    if (d < 0 || d >= from)
      throw new Error(`invalid integer: ${d}`);
    return d;
  });
  const dlen = digits.length;
  while (true) {
    let carry = 0;
    let done = true;
    for (let i = pos;i < dlen; i++) {
      const digit = digits[i];
      const fromCarry = from * carry;
      const digitBase = fromCarry + digit;
      if (!Number.isSafeInteger(digitBase) || fromCarry / from !== carry || digitBase - digit !== fromCarry) {
        throw new Error("convertRadix: carry overflow");
      }
      const div = digitBase / to;
      carry = digitBase % to;
      const rounded = Math.floor(div);
      digits[i] = rounded;
      if (!Number.isSafeInteger(rounded) || rounded * to + carry !== digitBase)
        throw new Error("convertRadix: carry overflow");
      if (!done)
        continue;
      else if (!rounded)
        pos = i;
      else
        done = false;
    }
    res.push(carry);
    if (done)
      break;
  }
  for (let i = 0;i < data.length - 1 && data[i] === 0; i++)
    res.push(0);
  return res.reverse();
}
var gcd = (a, b) => b === 0 ? a : gcd(b, a % b);
var radix2carry = (from, to) => from + (to - gcd(from, to));
var powers = /* @__PURE__ */ (() => {
  let res = [];
  for (let i = 0;i < 40; i++)
    res.push(2 ** i);
  return res;
})();
function convertRadix2(data, from, to, padding2) {
  aArr(data);
  if (from <= 0 || from > 32)
    throw new Error(`convertRadix2: wrong from=${from}`);
  if (to <= 0 || to > 32)
    throw new Error(`convertRadix2: wrong to=${to}`);
  if (radix2carry(from, to) > 32) {
    throw new Error(`convertRadix2: carry overflow from=${from} to=${to} carryBits=${radix2carry(from, to)}`);
  }
  let carry = 0;
  let pos = 0;
  const max = powers[from];
  const mask = powers[to] - 1;
  const res = [];
  for (const n of data) {
    anumber2(n);
    if (n >= max)
      throw new Error(`convertRadix2: invalid data word=${n} from=${from}`);
    carry = carry << from | n;
    if (pos + from > 32)
      throw new Error(`convertRadix2: carry overflow pos=${pos} from=${from}`);
    pos += from;
    for (;pos >= to; pos -= to)
      res.push((carry >> pos - to & mask) >>> 0);
    const pow3 = powers[pos];
    if (pow3 === undefined)
      throw new Error("invalid carry");
    carry &= pow3 - 1;
  }
  carry = carry << to - pos & mask;
  if (!padding2 && pos >= from)
    throw new Error("Excess padding");
  if (!padding2 && carry > 0)
    throw new Error(`Non-zero padding: ${carry}`);
  if (padding2 && pos > 0)
    res.push(carry >>> 0);
  return res;
}
function radix(num2) {
  anumber2(num2);
  const _256 = 2 ** 8;
  return {
    encode: (bytes) => {
      if (!isBytes3(bytes))
        throw new Error("radix.encode input should be Uint8Array");
      return convertRadix(Array.from(bytes), _256, num2);
    },
    decode: (digits) => {
      anumArr("radix.decode", digits);
      return Uint8Array.from(convertRadix(digits, num2, _256));
    }
  };
}
function radix2(bits, revPadding = false) {
  anumber2(bits);
  if (bits <= 0 || bits > 32)
    throw new Error("radix2: bits should be in (0..32]");
  if (radix2carry(8, bits) > 32 || radix2carry(bits, 8) > 32)
    throw new Error("radix2: carry overflow");
  return {
    encode: (bytes) => {
      if (!isBytes3(bytes))
        throw new Error("radix2.encode input should be Uint8Array");
      return convertRadix2(Array.from(bytes), 8, bits, !revPadding);
    },
    decode: (digits) => {
      anumArr("radix2.decode", digits);
      return Uint8Array.from(convertRadix2(digits, bits, 8, revPadding));
    }
  };
}
function unsafeWrapper(fn) {
  afn(fn);
  return function(...args) {
    try {
      return fn.apply(null, args);
    } catch (e) {}
  };
}
function checksum(len, fn) {
  anumber2(len);
  afn(fn);
  return {
    encode(data) {
      if (!isBytes3(data))
        throw new Error("checksum.encode: input should be Uint8Array");
      const sum = fn(data).slice(0, len);
      const res = new Uint8Array(data.length + len);
      res.set(data);
      res.set(sum, data.length);
      return res;
    },
    decode(data) {
      if (!isBytes3(data))
        throw new Error("checksum.decode: input should be Uint8Array");
      const payload = data.slice(0, -len);
      const oldChecksum = data.slice(-len);
      const newChecksum = fn(payload).slice(0, len);
      for (let i = 0;i < len; i++)
        if (newChecksum[i] !== oldChecksum[i])
          throw new Error("Invalid checksum");
      return payload;
    }
  };
}
var base16 = chain(radix2(4), alphabet("0123456789ABCDEF"), join(""));
var base32 = chain(radix2(5), alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"), padding(5), join(""));
var base32nopad = chain(radix2(5), alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"), join(""));
var base32hex = chain(radix2(5), alphabet("0123456789ABCDEFGHIJKLMNOPQRSTUV"), padding(5), join(""));
var base32hexnopad = chain(radix2(5), alphabet("0123456789ABCDEFGHIJKLMNOPQRSTUV"), join(""));
var base32crockford = chain(radix2(5), alphabet("0123456789ABCDEFGHJKMNPQRSTVWXYZ"), join(""), normalize((s) => s.toUpperCase().replace(/O/g, "0").replace(/[IL]/g, "1")));
var hasBase64Builtin = /* @__PURE__ */ (() => typeof Uint8Array.from([]).toBase64 === "function" && typeof Uint8Array.fromBase64 === "function")();
var decodeBase64Builtin = (s, isUrl) => {
  astr("base64", s);
  const re = isUrl ? /^[A-Za-z0-9=_-]+$/ : /^[A-Za-z0-9=+/]+$/;
  const alphabet2 = isUrl ? "base64url" : "base64";
  if (s.length > 0 && !re.test(s))
    throw new Error("invalid base64");
  return Uint8Array.fromBase64(s, { alphabet: alphabet2, lastChunkHandling: "strict" });
};
var base64 = hasBase64Builtin ? {
  encode(b) {
    abytes3(b);
    return b.toBase64();
  },
  decode(s) {
    return decodeBase64Builtin(s, false);
  }
} : chain(radix2(6), alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"), padding(6), join(""));
var base64nopad = chain(radix2(6), alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"), join(""));
var base64url = hasBase64Builtin ? {
  encode(b) {
    abytes3(b);
    return b.toBase64({ alphabet: "base64url" });
  },
  decode(s) {
    return decodeBase64Builtin(s, true);
  }
} : chain(radix2(6), alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"), padding(6), join(""));
var base64urlnopad = chain(radix2(6), alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"), join(""));
var genBase58 = (abc) => chain(radix(58), alphabet(abc), join(""));
var base58 = genBase58("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz");
var base58flickr = genBase58("123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ");
var base58xrp = genBase58("rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz");
var createBase58check = (sha2562) => chain(checksum(4, (data) => sha2562(sha2562(data))), base58);
var BECH_ALPHABET = chain(alphabet("qpzry9x8gf2tvdw0s3jn54khce6mua7l"), join(""));
var POLYMOD_GENERATORS = [996825010, 642813549, 513874426, 1027748829, 705979059];
function bech32Polymod(pre) {
  const b = pre >> 25;
  let chk = (pre & 33554431) << 5;
  for (let i = 0;i < POLYMOD_GENERATORS.length; i++) {
    if ((b >> i & 1) === 1)
      chk ^= POLYMOD_GENERATORS[i];
  }
  return chk;
}
function bechChecksum(prefix, words, encodingConst = 1) {
  const len = prefix.length;
  let chk = 1;
  for (let i = 0;i < len; i++) {
    const c = prefix.charCodeAt(i);
    if (c < 33 || c > 126)
      throw new Error(`Invalid prefix (${prefix})`);
    chk = bech32Polymod(chk) ^ c >> 5;
  }
  chk = bech32Polymod(chk);
  for (let i = 0;i < len; i++)
    chk = bech32Polymod(chk) ^ prefix.charCodeAt(i) & 31;
  for (let v of words)
    chk = bech32Polymod(chk) ^ v;
  for (let i = 0;i < 6; i++)
    chk = bech32Polymod(chk);
  chk ^= encodingConst;
  return BECH_ALPHABET.encode(convertRadix2([chk % powers[30]], 30, 5, false));
}
function genBech32(encoding) {
  const ENCODING_CONST = encoding === "bech32" ? 1 : 734539939;
  const _words = radix2(5);
  const fromWords = _words.decode;
  const toWords = _words.encode;
  const fromWordsUnsafe = unsafeWrapper(fromWords);
  function encode(prefix, words, limit = 90) {
    astr("bech32.encode prefix", prefix);
    if (isBytes3(words))
      words = Array.from(words);
    anumArr("bech32.encode", words);
    const plen = prefix.length;
    if (plen === 0)
      throw new TypeError(`Invalid prefix length ${plen}`);
    const actualLength = plen + 7 + words.length;
    if (limit !== false && actualLength > limit)
      throw new TypeError(`Length ${actualLength} exceeds limit ${limit}`);
    const lowered = prefix.toLowerCase();
    const sum = bechChecksum(lowered, words, ENCODING_CONST);
    return `${lowered}1${BECH_ALPHABET.encode(words)}${sum}`;
  }
  function decode(str, limit = 90) {
    astr("bech32.decode input", str);
    const slen = str.length;
    if (slen < 8 || limit !== false && slen > limit)
      throw new TypeError(`invalid string length: ${slen} (${str}). Expected (8..${limit})`);
    const lowered = str.toLowerCase();
    if (str !== lowered && str !== str.toUpperCase())
      throw new Error(`String must be lowercase or uppercase`);
    const sepIndex = lowered.lastIndexOf("1");
    if (sepIndex === 0 || sepIndex === -1)
      throw new Error(`Letter "1" must be present between prefix and data only`);
    const prefix = lowered.slice(0, sepIndex);
    const data = lowered.slice(sepIndex + 1);
    if (data.length < 6)
      throw new Error("Data must be at least 6 characters long");
    const words = BECH_ALPHABET.decode(data).slice(0, -6);
    const sum = bechChecksum(prefix, words, ENCODING_CONST);
    if (!data.endsWith(sum))
      throw new Error(`Invalid checksum in ${str}: expected "${sum}"`);
    return { prefix, words };
  }
  const decodeUnsafe = unsafeWrapper(decode);
  function decodeToBytes(str) {
    const { prefix, words } = decode(str, false);
    return { prefix, words, bytes: fromWords(words) };
  }
  function encodeFromBytes(prefix, bytes) {
    return encode(prefix, toWords(bytes));
  }
  return {
    encode,
    decode,
    encodeFromBytes,
    decodeToBytes,
    decodeUnsafe,
    fromWords,
    fromWordsUnsafe,
    toWords
  };
}
var bech32 = genBech32("bech32");
var bech32m = genBech32("bech32m");
var utf8 = {
  encode: (data) => new TextDecoder().decode(data),
  decode: (str) => new TextEncoder().encode(str)
};
var hasHexBuiltin = /* @__PURE__ */ (() => typeof Uint8Array.from([]).toHex === "function" && typeof Uint8Array.fromHex === "function")();
var hexBuiltin = {
  encode(data) {
    abytes3(data);
    return data.toHex();
  },
  decode(s) {
    astr("hex", s);
    return Uint8Array.fromHex(s);
  }
};
var hex = hasHexBuiltin ? hexBuiltin : chain(radix2(4), alphabet("0123456789abcdef"), join(""), normalize((s) => {
  if (typeof s !== "string" || s.length % 2 !== 0)
    throw new TypeError(`hex.decode: expected string, got ${typeof s} with length ${s.length}`);
  return s.toLowerCase();
}));

// node_modules/micro-packed/lib/esm/index.js
var EMPTY = /* @__PURE__ */ new Uint8Array;
var NULL = /* @__PURE__ */ new Uint8Array([0]);
function equalBytes2(a, b) {
  if (a.length !== b.length)
    return false;
  for (let i = 0;i < a.length; i++)
    if (a[i] !== b[i])
      return false;
  return true;
}
function isBytes4(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
}
function concatBytes3(...arrays) {
  let sum = 0;
  for (let i = 0;i < arrays.length; i++) {
    const a = arrays[i];
    if (!isBytes4(a))
      throw new Error("Uint8Array expected");
    sum += a.length;
  }
  const res = new Uint8Array(sum);
  for (let i = 0, pad = 0;i < arrays.length; i++) {
    const a = arrays[i];
    res.set(a, pad);
    pad += a.length;
  }
  return res;
}
var createView2 = (arr) => new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
function isPlainObject(obj) {
  return Object.prototype.toString.call(obj) === "[object Object]";
}
function isNum(num2) {
  return Number.isSafeInteger(num2);
}
var utils = {
  equalBytes: equalBytes2,
  isBytes: isBytes4,
  isCoder,
  checkBounds,
  concatBytes: concatBytes3,
  createView: createView2,
  isPlainObject
};
var lengthCoder = (len) => {
  if (len !== null && typeof len !== "string" && !isCoder(len) && !isBytes4(len) && !isNum(len)) {
    throw new Error(`lengthCoder: expected null | number | Uint8Array | CoderType, got ${len} (${typeof len})`);
  }
  return {
    encodeStream(w, value) {
      if (len === null)
        return;
      if (isCoder(len))
        return len.encodeStream(w, value);
      let byteLen;
      if (typeof len === "number")
        byteLen = len;
      else if (typeof len === "string")
        byteLen = Path.resolve(w.stack, len);
      if (typeof byteLen === "bigint")
        byteLen = Number(byteLen);
      if (byteLen === undefined || byteLen !== value)
        throw w.err(`Wrong length: ${byteLen} len=${len} exp=${value} (${typeof value})`);
    },
    decodeStream(r) {
      let byteLen;
      if (isCoder(len))
        byteLen = Number(len.decodeStream(r));
      else if (typeof len === "number")
        byteLen = len;
      else if (typeof len === "string")
        byteLen = Path.resolve(r.stack, len);
      if (typeof byteLen === "bigint")
        byteLen = Number(byteLen);
      if (typeof byteLen !== "number")
        throw r.err(`Wrong length: ${byteLen}`);
      return byteLen;
    }
  };
};
var Bitset = {
  BITS: 32,
  FULL_MASK: -1 >>> 0,
  len: (len) => Math.ceil(len / 32),
  create: (len) => new Uint32Array(Bitset.len(len)),
  clean: (bs) => bs.fill(0),
  debug: (bs) => Array.from(bs).map((i) => (i >>> 0).toString(2).padStart(32, "0")),
  checkLen: (bs, len) => {
    if (Bitset.len(len) === bs.length)
      return;
    throw new Error(`wrong length=${bs.length}. Expected: ${Bitset.len(len)}`);
  },
  chunkLen: (bsLen, pos, len) => {
    if (pos < 0)
      throw new Error(`wrong pos=${pos}`);
    if (pos + len > bsLen)
      throw new Error(`wrong range=${pos}/${len} of ${bsLen}`);
  },
  set: (bs, chunk, value, allowRewrite = true) => {
    if (!allowRewrite && (bs[chunk] & value) !== 0)
      return false;
    bs[chunk] |= value;
    return true;
  },
  pos: (pos, i) => ({
    chunk: Math.floor((pos + i) / 32),
    mask: 1 << 32 - (pos + i) % 32 - 1
  }),
  indices: (bs, len, invert2 = false) => {
    Bitset.checkLen(bs, len);
    const { FULL_MASK, BITS } = Bitset;
    const left = BITS - len % BITS;
    const lastMask = left ? FULL_MASK >>> left << left : FULL_MASK;
    const res = [];
    for (let i = 0;i < bs.length; i++) {
      let c = bs[i];
      if (invert2)
        c = ~c;
      if (i === bs.length - 1)
        c &= lastMask;
      if (c === 0)
        continue;
      for (let j = 0;j < BITS; j++) {
        const m = 1 << BITS - j - 1;
        if (c & m)
          res.push(i * BITS + j);
      }
    }
    return res;
  },
  range: (arr) => {
    const res = [];
    let cur;
    for (const i of arr) {
      if (cur === undefined || i !== cur.pos + cur.length)
        res.push(cur = { pos: i, length: 1 });
      else
        cur.length += 1;
    }
    return res;
  },
  rangeDebug: (bs, len, invert2 = false) => `[${Bitset.range(Bitset.indices(bs, len, invert2)).map((i) => `(${i.pos}/${i.length})`).join(", ")}]`,
  setRange: (bs, bsLen, pos, len, allowRewrite = true) => {
    Bitset.chunkLen(bsLen, pos, len);
    const { FULL_MASK, BITS } = Bitset;
    const first = pos % BITS ? Math.floor(pos / BITS) : undefined;
    const lastPos = pos + len;
    const last = lastPos % BITS ? Math.floor(lastPos / BITS) : undefined;
    if (first !== undefined && first === last)
      return Bitset.set(bs, first, FULL_MASK >>> BITS - len << BITS - len - pos, allowRewrite);
    if (first !== undefined) {
      if (!Bitset.set(bs, first, FULL_MASK >>> pos % BITS, allowRewrite))
        return false;
    }
    const start = first !== undefined ? first + 1 : pos / BITS;
    const end = last !== undefined ? last : lastPos / BITS;
    for (let i = start;i < end; i++)
      if (!Bitset.set(bs, i, FULL_MASK, allowRewrite))
        return false;
    if (last !== undefined && first !== last) {
      if (!Bitset.set(bs, last, FULL_MASK << BITS - lastPos % BITS, allowRewrite))
        return false;
    }
    return true;
  }
};
var Path = {
  pushObj: (stack, obj, objFn) => {
    const last = { obj };
    stack.push(last);
    objFn((field, fieldFn) => {
      last.field = field;
      fieldFn();
      last.field = undefined;
    });
    stack.pop();
  },
  path: (stack) => {
    const res = [];
    for (const i of stack)
      if (i.field !== undefined)
        res.push(i.field);
    return res.join("/");
  },
  err: (name, stack, msg) => {
    const err = new Error(`${name}(${Path.path(stack)}): ${typeof msg === "string" ? msg : msg.message}`);
    if (msg instanceof Error && msg.stack)
      err.stack = msg.stack;
    return err;
  },
  resolve: (stack, path) => {
    const parts = path.split("/");
    const objPath = stack.map((i2) => i2.obj);
    let i = 0;
    for (;i < parts.length; i++) {
      if (parts[i] === "..")
        objPath.pop();
      else
        break;
    }
    let cur = objPath.pop();
    for (;i < parts.length; i++) {
      if (!cur || cur[parts[i]] === undefined)
        return;
      cur = cur[parts[i]];
    }
    return cur;
  }
};

class _Reader {
  constructor(data, opts = {}, stack = [], parent = undefined, parentOffset = 0) {
    this.pos = 0;
    this.bitBuf = 0;
    this.bitPos = 0;
    this.data = data;
    this.opts = opts;
    this.stack = stack;
    this.parent = parent;
    this.parentOffset = parentOffset;
    this.view = createView2(data);
  }
  _enablePointers() {
    if (this.parent)
      return this.parent._enablePointers();
    if (this.bs)
      return;
    this.bs = Bitset.create(this.data.length);
    Bitset.setRange(this.bs, this.data.length, 0, this.pos, this.opts.allowMultipleReads);
  }
  markBytesBS(pos, len) {
    if (this.parent)
      return this.parent.markBytesBS(this.parentOffset + pos, len);
    if (!len)
      return true;
    if (!this.bs)
      return true;
    return Bitset.setRange(this.bs, this.data.length, pos, len, false);
  }
  markBytes(len) {
    const pos = this.pos;
    this.pos += len;
    const res = this.markBytesBS(pos, len);
    if (!this.opts.allowMultipleReads && !res)
      throw this.err(`multiple read pos=${this.pos} len=${len}`);
    return res;
  }
  pushObj(obj, objFn) {
    return Path.pushObj(this.stack, obj, objFn);
  }
  readView(n, fn) {
    if (!Number.isFinite(n))
      throw this.err(`readView: wrong length=${n}`);
    if (this.pos + n > this.data.length)
      throw this.err("readView: Unexpected end of buffer");
    const res = fn(this.view, this.pos);
    this.markBytes(n);
    return res;
  }
  absBytes(n) {
    if (n > this.data.length)
      throw new Error("Unexpected end of buffer");
    return this.data.subarray(n);
  }
  finish() {
    if (this.opts.allowUnreadBytes)
      return;
    if (this.bitPos) {
      throw this.err(`${this.bitPos} bits left after unpack: ${hex.encode(this.data.slice(this.pos))}`);
    }
    if (this.bs && !this.parent) {
      const notRead = Bitset.indices(this.bs, this.data.length, true);
      if (notRead.length) {
        const formatted = Bitset.range(notRead).map(({ pos, length }) => `(${pos}/${length})[${hex.encode(this.data.subarray(pos, pos + length))}]`).join(", ");
        throw this.err(`unread byte ranges: ${formatted} (total=${this.data.length})`);
      } else
        return;
    }
    if (!this.isEnd()) {
      throw this.err(`${this.leftBytes} bytes ${this.bitPos} bits left after unpack: ${hex.encode(this.data.slice(this.pos))}`);
    }
  }
  err(msg) {
    return Path.err("Reader", this.stack, msg);
  }
  offsetReader(n) {
    if (n > this.data.length)
      throw this.err("offsetReader: Unexpected end of buffer");
    return new _Reader(this.absBytes(n), this.opts, this.stack, this, n);
  }
  bytes(n, peek = false) {
    if (this.bitPos)
      throw this.err("readBytes: bitPos not empty");
    if (!Number.isFinite(n))
      throw this.err(`readBytes: wrong length=${n}`);
    if (this.pos + n > this.data.length)
      throw this.err("readBytes: Unexpected end of buffer");
    const slice = this.data.subarray(this.pos, this.pos + n);
    if (!peek)
      this.markBytes(n);
    return slice;
  }
  byte(peek = false) {
    if (this.bitPos)
      throw this.err("readByte: bitPos not empty");
    if (this.pos + 1 > this.data.length)
      throw this.err("readBytes: Unexpected end of buffer");
    const data = this.data[this.pos];
    if (!peek)
      this.markBytes(1);
    return data;
  }
  get leftBytes() {
    return this.data.length - this.pos;
  }
  get totalBytes() {
    return this.data.length;
  }
  isEnd() {
    return this.pos >= this.data.length && !this.bitPos;
  }
  bits(bits) {
    if (bits > 32)
      throw this.err("BitReader: cannot read more than 32 bits in single call");
    let out = 0;
    while (bits) {
      if (!this.bitPos) {
        this.bitBuf = this.byte();
        this.bitPos = 8;
      }
      const take = Math.min(bits, this.bitPos);
      this.bitPos -= take;
      out = out << take | this.bitBuf >> this.bitPos & 2 ** take - 1;
      this.bitBuf &= 2 ** this.bitPos - 1;
      bits -= take;
    }
    return out >>> 0;
  }
  find(needle, pos = this.pos) {
    if (!isBytes4(needle))
      throw this.err(`find: needle is not bytes! ${needle}`);
    if (this.bitPos)
      throw this.err("findByte: bitPos not empty");
    if (!needle.length)
      throw this.err(`find: needle is empty`);
    for (let idx = pos;(idx = this.data.indexOf(needle[0], idx)) !== -1; idx++) {
      if (idx === -1)
        return;
      const leftBytes = this.data.length - idx;
      if (leftBytes < needle.length)
        return;
      if (equalBytes2(needle, this.data.subarray(idx, idx + needle.length)))
        return idx;
    }
    return;
  }
}

class _Writer {
  constructor(stack = []) {
    this.pos = 0;
    this.buffers = [];
    this.ptrs = [];
    this.bitBuf = 0;
    this.bitPos = 0;
    this.viewBuf = new Uint8Array(8);
    this.finished = false;
    this.stack = stack;
    this.view = createView2(this.viewBuf);
  }
  pushObj(obj, objFn) {
    return Path.pushObj(this.stack, obj, objFn);
  }
  writeView(len, fn) {
    if (this.finished)
      throw this.err("buffer: finished");
    if (!isNum(len) || len > 8)
      throw new Error(`wrong writeView length=${len}`);
    fn(this.view);
    this.bytes(this.viewBuf.slice(0, len));
    this.viewBuf.fill(0);
  }
  err(msg) {
    if (this.finished)
      throw this.err("buffer: finished");
    return Path.err("Reader", this.stack, msg);
  }
  bytes(b) {
    if (this.finished)
      throw this.err("buffer: finished");
    if (this.bitPos)
      throw this.err("writeBytes: ends with non-empty bit buffer");
    this.buffers.push(b);
    this.pos += b.length;
  }
  byte(b) {
    if (this.finished)
      throw this.err("buffer: finished");
    if (this.bitPos)
      throw this.err("writeByte: ends with non-empty bit buffer");
    this.buffers.push(new Uint8Array([b]));
    this.pos++;
  }
  finish(clean = true) {
    if (this.finished)
      throw this.err("buffer: finished");
    if (this.bitPos)
      throw this.err("buffer: ends with non-empty bit buffer");
    const buffers = this.buffers.concat(this.ptrs.map((i) => i.buffer));
    const sum = buffers.map((b) => b.length).reduce((a, b) => a + b, 0);
    const buf = new Uint8Array(sum);
    for (let i = 0, pad = 0;i < buffers.length; i++) {
      const a = buffers[i];
      buf.set(a, pad);
      pad += a.length;
    }
    for (let pos = this.pos, i = 0;i < this.ptrs.length; i++) {
      const ptr = this.ptrs[i];
      buf.set(ptr.ptr.encode(pos), ptr.pos);
      pos += ptr.buffer.length;
    }
    if (clean) {
      this.buffers = [];
      for (const p of this.ptrs)
        p.buffer.fill(0);
      this.ptrs = [];
      this.finished = true;
      this.bitBuf = 0;
    }
    return buf;
  }
  bits(value, bits) {
    if (bits > 32)
      throw this.err("writeBits: cannot write more than 32 bits in single call");
    if (value >= 2 ** bits)
      throw this.err(`writeBits: value (${value}) >= 2**bits (${bits})`);
    while (bits) {
      const take = Math.min(bits, 8 - this.bitPos);
      this.bitBuf = this.bitBuf << take | value >> bits - take;
      this.bitPos += take;
      bits -= take;
      value &= 2 ** bits - 1;
      if (this.bitPos === 8) {
        this.bitPos = 0;
        this.buffers.push(new Uint8Array([this.bitBuf]));
        this.pos++;
      }
    }
  }
}
var swapEndianness = (b) => Uint8Array.from(b).reverse();
function checkBounds(value, bits, signed) {
  if (signed) {
    const signBit = 2n ** (bits - 1n);
    if (value < -signBit || value >= signBit)
      throw new Error(`value out of signed bounds. Expected ${-signBit} <= ${value} < ${signBit}`);
  } else {
    if (0n > value || value >= 2n ** bits)
      throw new Error(`value out of unsigned bounds. Expected 0 <= ${value} < ${2n ** bits}`);
  }
}
function _wrap(inner) {
  return {
    encodeStream: inner.encodeStream,
    decodeStream: inner.decodeStream,
    size: inner.size,
    encode: (value) => {
      const w = new _Writer;
      inner.encodeStream(w, value);
      return w.finish();
    },
    decode: (data, opts = {}) => {
      const r = new _Reader(data, opts);
      const res = inner.decodeStream(r);
      r.finish();
      return res;
    }
  };
}
function validate(inner, fn) {
  if (!isCoder(inner))
    throw new Error(`validate: invalid inner value ${inner}`);
  if (typeof fn !== "function")
    throw new Error("validate: fn should be function");
  return _wrap({
    size: inner.size,
    encodeStream: (w, value) => {
      let res;
      try {
        res = fn(value);
      } catch (e) {
        throw w.err(e);
      }
      inner.encodeStream(w, res);
    },
    decodeStream: (r) => {
      const res = inner.decodeStream(r);
      try {
        return fn(res);
      } catch (e) {
        throw r.err(e);
      }
    }
  });
}
var wrap = (inner) => {
  const res = _wrap(inner);
  return inner.validate ? validate(res, inner.validate) : res;
};
var isBaseCoder = (elm) => isPlainObject(elm) && typeof elm.decode === "function" && typeof elm.encode === "function";
function isCoder(elm) {
  return isPlainObject(elm) && isBaseCoder(elm) && typeof elm.encodeStream === "function" && typeof elm.decodeStream === "function" && (elm.size === undefined || isNum(elm.size));
}
function dict() {
  return {
    encode: (from) => {
      if (!Array.isArray(from))
        throw new Error("array expected");
      const to = {};
      for (const item of from) {
        if (!Array.isArray(item) || item.length !== 2)
          throw new Error(`array of two elements expected`);
        const name = item[0];
        const value = item[1];
        if (to[name] !== undefined)
          throw new Error(`key(${name}) appears twice in struct`);
        to[name] = value;
      }
      return to;
    },
    decode: (to) => {
      if (!isPlainObject(to))
        throw new Error(`expected plain object, got ${to}`);
      return Object.entries(to);
    }
  };
}
var numberBigint = {
  encode: (from) => {
    if (typeof from !== "bigint")
      throw new Error(`expected bigint, got ${typeof from}`);
    if (from > BigInt(Number.MAX_SAFE_INTEGER))
      throw new Error(`element bigger than MAX_SAFE_INTEGER=${from}`);
    return Number(from);
  },
  decode: (to) => {
    if (!isNum(to))
      throw new Error("element is not a safe integer");
    return BigInt(to);
  }
};
function tsEnum(e) {
  if (!isPlainObject(e))
    throw new Error("plain object expected");
  return {
    encode: (from) => {
      if (!isNum(from) || !(from in e))
        throw new Error(`wrong value ${from}`);
      return e[from];
    },
    decode: (to) => {
      if (typeof to !== "string")
        throw new Error(`wrong value ${typeof to}`);
      return e[to];
    }
  };
}
function decimal(precision, round = false) {
  if (!isNum(precision))
    throw new Error(`decimal/precision: wrong value ${precision}`);
  if (typeof round !== "boolean")
    throw new Error(`decimal/round: expected boolean, got ${typeof round}`);
  const decimalMask = 10n ** BigInt(precision);
  return {
    encode: (from) => {
      if (typeof from !== "bigint")
        throw new Error(`expected bigint, got ${typeof from}`);
      let s = (from < 0n ? -from : from).toString(10);
      let sep = s.length - precision;
      if (sep < 0) {
        s = s.padStart(s.length - sep, "0");
        sep = 0;
      }
      let i = s.length - 1;
      for (;i >= sep && s[i] === "0"; i--)
        ;
      let int = s.slice(0, sep);
      let frac = s.slice(sep, i + 1);
      if (!int)
        int = "0";
      if (from < 0n)
        int = "-" + int;
      if (!frac)
        return int;
      return `${int}.${frac}`;
    },
    decode: (to) => {
      if (typeof to !== "string")
        throw new Error(`expected string, got ${typeof to}`);
      if (to === "-0")
        throw new Error(`negative zero is not allowed`);
      let neg = false;
      if (to.startsWith("-")) {
        neg = true;
        to = to.slice(1);
      }
      if (!/^(0|[1-9]\d*)(\.\d+)?$/.test(to))
        throw new Error(`wrong string value=${to}`);
      let sep = to.indexOf(".");
      sep = sep === -1 ? to.length : sep;
      const intS = to.slice(0, sep);
      const fracS = to.slice(sep + 1).replace(/0+$/, "");
      const int = BigInt(intS) * decimalMask;
      if (!round && fracS.length > precision) {
        throw new Error(`fractional part cannot be represented with this precision (num=${to}, prec=${precision})`);
      }
      const fracLen = Math.min(fracS.length, precision);
      const frac = BigInt(fracS.slice(0, fracLen)) * 10n ** BigInt(precision - fracLen);
      const value = int + frac;
      return neg ? -value : value;
    }
  };
}
function match(lst) {
  if (!Array.isArray(lst))
    throw new Error(`expected array, got ${typeof lst}`);
  for (const i of lst)
    if (!isBaseCoder(i))
      throw new Error(`wrong base coder ${i}`);
  return {
    encode: (from) => {
      for (const c of lst) {
        const elm = c.encode(from);
        if (elm !== undefined)
          return elm;
      }
      throw new Error(`match/encode: cannot find match in ${from}`);
    },
    decode: (to) => {
      for (const c of lst) {
        const elm = c.decode(to);
        if (elm !== undefined)
          return elm;
      }
      throw new Error(`match/decode: cannot find match in ${to}`);
    }
  };
}
var reverse = (coder) => {
  if (!isBaseCoder(coder))
    throw new Error("BaseCoder expected");
  return { encode: coder.decode, decode: coder.encode };
};
var coders = { dict, numberBigint, tsEnum, decimal, match, reverse };
var bigint = (size, le = false, signed = false, sized = true) => {
  if (!isNum(size))
    throw new Error(`bigint/size: wrong value ${size}`);
  if (typeof le !== "boolean")
    throw new Error(`bigint/le: expected boolean, got ${typeof le}`);
  if (typeof signed !== "boolean")
    throw new Error(`bigint/signed: expected boolean, got ${typeof signed}`);
  if (typeof sized !== "boolean")
    throw new Error(`bigint/sized: expected boolean, got ${typeof sized}`);
  const bLen = BigInt(size);
  const signBit = 2n ** (8n * bLen - 1n);
  return wrap({
    size: sized ? size : undefined,
    encodeStream: (w, value) => {
      if (signed && value < 0)
        value = value | signBit;
      const b = [];
      for (let i = 0;i < size; i++) {
        b.push(Number(value & 255n));
        value >>= 8n;
      }
      let res = new Uint8Array(b).reverse();
      if (!sized) {
        let pos = 0;
        for (pos = 0;pos < res.length; pos++)
          if (res[pos] !== 0)
            break;
        res = res.subarray(pos);
      }
      w.bytes(le ? res.reverse() : res);
    },
    decodeStream: (r) => {
      const value = r.bytes(sized ? size : Math.min(size, r.leftBytes));
      const b = le ? value : swapEndianness(value);
      let res = 0n;
      for (let i = 0;i < b.length; i++)
        res |= BigInt(b[i]) << 8n * BigInt(i);
      if (signed && res & signBit)
        res = (res ^ signBit) - signBit;
      return res;
    },
    validate: (value) => {
      if (typeof value !== "bigint")
        throw new Error(`bigint: invalid value: ${value}`);
      checkBounds(value, 8n * bLen, !!signed);
      return value;
    }
  });
};
var U256BE = /* @__PURE__ */ bigint(32, false);
var U64LE = /* @__PURE__ */ bigint(8, true);
var I64LE = /* @__PURE__ */ bigint(8, true, true);
var view = (len, opts) => wrap({
  size: len,
  encodeStream: (w, value) => w.writeView(len, (view2) => opts.write(view2, value)),
  decodeStream: (r) => r.readView(len, opts.read),
  validate: (value) => {
    if (typeof value !== "number")
      throw new Error(`viewCoder: expected number, got ${typeof value}`);
    if (opts.validate)
      opts.validate(value);
    return value;
  }
});
var intView = (len, signed, opts) => {
  const bits = len * 8;
  const signBit = 2 ** (bits - 1);
  const validateSigned = (value) => {
    if (!isNum(value))
      throw new Error(`sintView: value is not safe integer: ${value}`);
    if (value < -signBit || value >= signBit) {
      throw new Error(`sintView: value out of bounds. Expected ${-signBit} <= ${value} < ${signBit}`);
    }
  };
  const maxVal = 2 ** bits;
  const validateUnsigned = (value) => {
    if (!isNum(value))
      throw new Error(`uintView: value is not safe integer: ${value}`);
    if (0 > value || value >= maxVal) {
      throw new Error(`uintView: value out of bounds. Expected 0 <= ${value} < ${maxVal}`);
    }
  };
  return view(len, {
    write: opts.write,
    read: opts.read,
    validate: signed ? validateSigned : validateUnsigned
  });
};
var U32LE = /* @__PURE__ */ intView(4, false, {
  read: (view2, pos) => view2.getUint32(pos, true),
  write: (view2, value) => view2.setUint32(0, value, true)
});
var U32BE = /* @__PURE__ */ intView(4, false, {
  read: (view2, pos) => view2.getUint32(pos, false),
  write: (view2, value) => view2.setUint32(0, value, false)
});
var I32LE = /* @__PURE__ */ intView(4, true, {
  read: (view2, pos) => view2.getInt32(pos, true),
  write: (view2, value) => view2.setInt32(0, value, true)
});
var U16LE = /* @__PURE__ */ intView(2, false, {
  read: (view2, pos) => view2.getUint16(pos, true),
  write: (view2, value) => view2.setUint16(0, value, true)
});
var U8 = /* @__PURE__ */ intView(1, false, {
  read: (view2, pos) => view2.getUint8(pos),
  write: (view2, value) => view2.setUint8(0, value)
});
var createBytes = (len, le = false) => {
  if (typeof le !== "boolean")
    throw new Error(`bytes/le: expected boolean, got ${typeof le}`);
  const _length = lengthCoder(len);
  const _isb = isBytes4(len);
  return wrap({
    size: typeof len === "number" ? len : undefined,
    encodeStream: (w, value) => {
      if (!_isb)
        _length.encodeStream(w, value.length);
      w.bytes(le ? swapEndianness(value) : value);
      if (_isb)
        w.bytes(len);
    },
    decodeStream: (r) => {
      let bytes;
      if (_isb) {
        const tPos = r.find(len);
        if (!tPos)
          throw r.err(`bytes: cannot find terminator`);
        bytes = r.bytes(tPos - r.pos);
        r.bytes(len.length);
      } else {
        bytes = r.bytes(len === null ? r.leftBytes : _length.decodeStream(r));
      }
      return le ? swapEndianness(bytes) : bytes;
    },
    validate: (value) => {
      if (!isBytes4(value))
        throw new Error(`bytes: invalid value ${value}`);
      return value;
    }
  });
};
function prefix(len, inner) {
  if (!isCoder(inner))
    throw new Error(`prefix: invalid inner value ${inner}`);
  return apply(createBytes(len), reverse(inner));
}
var string = (len, le = false) => validate(apply(createBytes(len, le), utf8), (value) => {
  if (typeof value !== "string")
    throw new Error(`expected string, got ${typeof value}`);
  return value;
});
var createHex = (len, options = { isLE: false, with0x: false }) => {
  let inner = apply(createBytes(len, options.isLE), hex);
  const prefix2 = options.with0x;
  if (typeof prefix2 !== "boolean")
    throw new Error(`hex/with0x: expected boolean, got ${typeof prefix2}`);
  if (prefix2) {
    inner = apply(inner, {
      encode: (value) => `0x${value}`,
      decode: (value) => {
        if (!value.startsWith("0x"))
          throw new Error("hex(with0x=true).encode input should start with 0x");
        return value.slice(2);
      }
    });
  }
  return inner;
};
function apply(inner, base) {
  if (!isCoder(inner))
    throw new Error(`apply: invalid inner value ${inner}`);
  if (!isBaseCoder(base))
    throw new Error(`apply: invalid base value ${inner}`);
  return wrap({
    size: inner.size,
    encodeStream: (w, value) => {
      let innerValue;
      try {
        innerValue = base.decode(value);
      } catch (e) {
        throw w.err("" + e);
      }
      return inner.encodeStream(w, innerValue);
    },
    decodeStream: (r) => {
      const innerValue = inner.decodeStream(r);
      try {
        return base.encode(innerValue);
      } catch (e) {
        throw r.err("" + e);
      }
    }
  });
}
var flag = (flagValue, xor = false) => {
  if (!isBytes4(flagValue))
    throw new Error(`flag/flagValue: expected Uint8Array, got ${typeof flagValue}`);
  if (typeof xor !== "boolean")
    throw new Error(`flag/xor: expected boolean, got ${typeof xor}`);
  return wrap({
    size: flagValue.length,
    encodeStream: (w, value) => {
      if (!!value !== xor)
        w.bytes(flagValue);
    },
    decodeStream: (r) => {
      let hasFlag = r.leftBytes >= flagValue.length;
      if (hasFlag) {
        hasFlag = equalBytes2(r.bytes(flagValue.length, true), flagValue);
        if (hasFlag)
          r.bytes(flagValue.length);
      }
      return hasFlag !== xor;
    },
    validate: (value) => {
      if (value !== undefined && typeof value !== "boolean")
        throw new Error(`flag: expected boolean value or undefined, got ${typeof value}`);
      return value;
    }
  });
};
function flagged(path, inner, def) {
  if (!isCoder(inner))
    throw new Error(`flagged: invalid inner value ${inner}`);
  if (typeof path !== "string" && !isCoder(inner))
    throw new Error(`flagged: wrong path=${path}`);
  return wrap({
    encodeStream: (w, value) => {
      if (typeof path === "string") {
        if (Path.resolve(w.stack, path))
          inner.encodeStream(w, value);
        else if (def)
          inner.encodeStream(w, def);
      } else {
        path.encodeStream(w, !!value);
        if (!!value)
          inner.encodeStream(w, value);
        else if (def)
          inner.encodeStream(w, def);
      }
    },
    decodeStream: (r) => {
      let hasFlag = false;
      if (typeof path === "string")
        hasFlag = !!Path.resolve(r.stack, path);
      else
        hasFlag = path.decodeStream(r);
      if (hasFlag)
        return inner.decodeStream(r);
      else if (def)
        inner.decodeStream(r);
      return;
    }
  });
}
function magic(inner, constant, check = true) {
  if (!isCoder(inner))
    throw new Error(`magic: invalid inner value ${inner}`);
  if (typeof check !== "boolean")
    throw new Error(`magic: expected boolean, got ${typeof check}`);
  return wrap({
    size: inner.size,
    encodeStream: (w, _value) => inner.encodeStream(w, constant),
    decodeStream: (r) => {
      const value = inner.decodeStream(r);
      if (check && typeof value !== "object" && value !== constant || isBytes4(constant) && !equalBytes2(constant, value)) {
        throw r.err(`magic: invalid value: ${value} !== ${constant}`);
      }
      return;
    },
    validate: (value) => {
      if (value !== undefined)
        throw new Error(`magic: wrong value=${typeof value}`);
      return value;
    }
  });
}
function sizeof(fields) {
  let size = 0;
  for (const f2 of fields) {
    if (f2.size === undefined)
      return;
    if (!isNum(f2.size))
      throw new Error(`sizeof: wrong element size=${size}`);
    size += f2.size;
  }
  return size;
}
function struct(fields) {
  if (!isPlainObject(fields))
    throw new Error(`struct: expected plain object, got ${fields}`);
  for (const name in fields) {
    if (!isCoder(fields[name]))
      throw new Error(`struct: field ${name} is not CoderType`);
  }
  return wrap({
    size: sizeof(Object.values(fields)),
    encodeStream: (w, value) => {
      w.pushObj(value, (fieldFn) => {
        for (const name in fields)
          fieldFn(name, () => fields[name].encodeStream(w, value[name]));
      });
    },
    decodeStream: (r) => {
      const res = {};
      r.pushObj(res, (fieldFn) => {
        for (const name in fields)
          fieldFn(name, () => res[name] = fields[name].decodeStream(r));
      });
      return res;
    },
    validate: (value) => {
      if (typeof value !== "object" || value === null)
        throw new Error(`struct: invalid value ${value}`);
      return value;
    }
  });
}
function tuple(fields) {
  if (!Array.isArray(fields))
    throw new Error(`Packed.Tuple: got ${typeof fields} instead of array`);
  for (let i = 0;i < fields.length; i++) {
    if (!isCoder(fields[i]))
      throw new Error(`tuple: field ${i} is not CoderType`);
  }
  return wrap({
    size: sizeof(fields),
    encodeStream: (w, value) => {
      if (!Array.isArray(value))
        throw w.err(`tuple: invalid value ${value}`);
      w.pushObj(value, (fieldFn) => {
        for (let i = 0;i < fields.length; i++)
          fieldFn(`${i}`, () => fields[i].encodeStream(w, value[i]));
      });
    },
    decodeStream: (r) => {
      const res = [];
      r.pushObj(res, (fieldFn) => {
        for (let i = 0;i < fields.length; i++)
          fieldFn(`${i}`, () => res.push(fields[i].decodeStream(r)));
      });
      return res;
    },
    validate: (value) => {
      if (!Array.isArray(value))
        throw new Error(`tuple: invalid value ${value}`);
      if (value.length !== fields.length)
        throw new Error(`tuple: wrong length=${value.length}, expected ${fields.length}`);
      return value;
    }
  });
}
function array(len, inner) {
  if (!isCoder(inner))
    throw new Error(`array: invalid inner value ${inner}`);
  const _length = lengthCoder(typeof len === "string" ? `../${len}` : len);
  return wrap({
    size: typeof len === "number" && inner.size ? len * inner.size : undefined,
    encodeStream: (w, value) => {
      const _w = w;
      _w.pushObj(value, (fieldFn) => {
        if (!isBytes4(len))
          _length.encodeStream(w, value.length);
        for (let i = 0;i < value.length; i++) {
          fieldFn(`${i}`, () => {
            const elm = value[i];
            const startPos = w.pos;
            inner.encodeStream(w, elm);
            if (isBytes4(len)) {
              if (len.length > _w.pos - startPos)
                return;
              const data = _w.finish(false).subarray(startPos, _w.pos);
              if (equalBytes2(data.subarray(0, len.length), len))
                throw _w.err(`array: inner element encoding same as separator. elm=${elm} data=${data}`);
            }
          });
        }
      });
      if (isBytes4(len))
        w.bytes(len);
    },
    decodeStream: (r) => {
      const res = [];
      r.pushObj(res, (fieldFn) => {
        if (len === null) {
          for (let i = 0;!r.isEnd(); i++) {
            fieldFn(`${i}`, () => res.push(inner.decodeStream(r)));
            if (inner.size && r.leftBytes < inner.size)
              break;
          }
        } else if (isBytes4(len)) {
          for (let i = 0;; i++) {
            if (equalBytes2(r.bytes(len.length, true), len)) {
              r.bytes(len.length);
              break;
            }
            fieldFn(`${i}`, () => res.push(inner.decodeStream(r)));
          }
        } else {
          let length;
          fieldFn("arrayLen", () => length = _length.decodeStream(r));
          for (let i = 0;i < length; i++)
            fieldFn(`${i}`, () => res.push(inner.decodeStream(r)));
        }
      });
      return res;
    },
    validate: (value) => {
      if (!Array.isArray(value))
        throw new Error(`array: invalid value ${value}`);
      return value;
    }
  });
}

// node_modules/@scure/btc-signer/esm/utils.js
var Point2 = secp256k1.ProjectivePoint;
var CURVE_ORDER = secp256k1.CURVE.n;
var isBytes5 = utils.isBytes;
var concatBytes4 = utils.concatBytes;
var equalBytes3 = utils.equalBytes;
var hash160 = (msg) => ripemd160(sha256(msg));
var sha256x2 = (...msgs) => sha256(sha256(concatBytes4(...msgs)));
var randomPrivateKeyBytes = schnorr.utils.randomPrivateKey;
var pubSchnorr = schnorr.getPublicKey;
var pubECDSA = secp256k1.getPublicKey;
var hasLowR = (sig) => sig.r < CURVE_ORDER / 2n;
function signECDSA(hash, privateKey, lowR = false) {
  let sig = secp256k1.sign(hash, privateKey);
  if (lowR && !hasLowR(sig)) {
    const extraEntropy = new Uint8Array(32);
    let counter = 0;
    while (!hasLowR(sig)) {
      extraEntropy.set(U32LE.encode(counter++));
      sig = secp256k1.sign(hash, privateKey, { extraEntropy });
      if (counter > 4294967295)
        throw new Error("lowR counter overflow: report the error");
    }
  }
  return sig.toDERRawBytes();
}
var signSchnorr = schnorr.sign;
var tagSchnorr = schnorr.utils.taggedHash;
var PubT;
(function(PubT2) {
  PubT2[PubT2["ecdsa"] = 0] = "ecdsa";
  PubT2[PubT2["schnorr"] = 1] = "schnorr";
})(PubT || (PubT = {}));
function validatePubkey(pub, type) {
  const len = pub.length;
  if (type === PubT.ecdsa) {
    if (len === 32)
      throw new Error("Expected non-Schnorr key");
    Point2.fromHex(pub);
    return pub;
  } else if (type === PubT.schnorr) {
    if (len !== 32)
      throw new Error("Expected 32-byte Schnorr key");
    schnorr.utils.lift_x(schnorr.utils.bytesToNumberBE(pub));
    return pub;
  } else {
    throw new Error("Unknown key type");
  }
}
function tapTweak(a, b) {
  const u = schnorr.utils;
  const t = u.taggedHash("TapTweak", a, b);
  const tn = u.bytesToNumberBE(t);
  if (tn >= CURVE_ORDER)
    throw new Error("tweak higher than curve order");
  return tn;
}
function taprootTweakPrivKey(privKey, merkleRoot = new Uint8Array) {
  const u = schnorr.utils;
  const seckey0 = u.bytesToNumberBE(privKey);
  const P = Point2.fromPrivateKey(seckey0);
  const seckey = P.hasEvenY() ? seckey0 : u.mod(-seckey0, CURVE_ORDER);
  const xP = u.pointToBytes(P);
  const t = tapTweak(xP, merkleRoot);
  return u.numberToBytesBE(u.mod(seckey + t, CURVE_ORDER), 32);
}
function taprootTweakPubkey(pubKey, h) {
  const u = schnorr.utils;
  const t = tapTweak(pubKey, h);
  const P = u.lift_x(u.bytesToNumberBE(pubKey));
  const Q = P.add(Point2.fromPrivateKey(t));
  const parity = Q.hasEvenY() ? 0 : 1;
  return [u.pointToBytes(Q), parity];
}
var TAPROOT_UNSPENDABLE_KEY = sha256(Point2.BASE.toRawBytes(false));
var NETWORK = {
  bech32: "bc",
  pubKeyHash: 0,
  scriptHash: 5,
  wif: 128
};
var TEST_NETWORK = {
  bech32: "tb",
  pubKeyHash: 111,
  scriptHash: 196,
  wif: 239
};
function compareBytes(a, b) {
  if (!isBytes5(a) || !isBytes5(b))
    throw new Error(`cmp: wrong type a=${typeof a} b=${typeof b}`);
  const len = Math.min(a.length, b.length);
  for (let i = 0;i < len; i++)
    if (a[i] != b[i])
      return Math.sign(a[i] - b[i]);
  return Math.sign(a.length - b.length);
}

// node_modules/@scure/btc-signer/esm/script.js
var OP;
(function(OP2) {
  OP2[OP2["OP_0"] = 0] = "OP_0";
  OP2[OP2["PUSHDATA1"] = 76] = "PUSHDATA1";
  OP2[OP2["PUSHDATA2"] = 77] = "PUSHDATA2";
  OP2[OP2["PUSHDATA4"] = 78] = "PUSHDATA4";
  OP2[OP2["1NEGATE"] = 79] = "1NEGATE";
  OP2[OP2["RESERVED"] = 80] = "RESERVED";
  OP2[OP2["OP_1"] = 81] = "OP_1";
  OP2[OP2["OP_2"] = 82] = "OP_2";
  OP2[OP2["OP_3"] = 83] = "OP_3";
  OP2[OP2["OP_4"] = 84] = "OP_4";
  OP2[OP2["OP_5"] = 85] = "OP_5";
  OP2[OP2["OP_6"] = 86] = "OP_6";
  OP2[OP2["OP_7"] = 87] = "OP_7";
  OP2[OP2["OP_8"] = 88] = "OP_8";
  OP2[OP2["OP_9"] = 89] = "OP_9";
  OP2[OP2["OP_10"] = 90] = "OP_10";
  OP2[OP2["OP_11"] = 91] = "OP_11";
  OP2[OP2["OP_12"] = 92] = "OP_12";
  OP2[OP2["OP_13"] = 93] = "OP_13";
  OP2[OP2["OP_14"] = 94] = "OP_14";
  OP2[OP2["OP_15"] = 95] = "OP_15";
  OP2[OP2["OP_16"] = 96] = "OP_16";
  OP2[OP2["NOP"] = 97] = "NOP";
  OP2[OP2["VER"] = 98] = "VER";
  OP2[OP2["IF"] = 99] = "IF";
  OP2[OP2["NOTIF"] = 100] = "NOTIF";
  OP2[OP2["VERIF"] = 101] = "VERIF";
  OP2[OP2["VERNOTIF"] = 102] = "VERNOTIF";
  OP2[OP2["ELSE"] = 103] = "ELSE";
  OP2[OP2["ENDIF"] = 104] = "ENDIF";
  OP2[OP2["VERIFY"] = 105] = "VERIFY";
  OP2[OP2["RETURN"] = 106] = "RETURN";
  OP2[OP2["TOALTSTACK"] = 107] = "TOALTSTACK";
  OP2[OP2["FROMALTSTACK"] = 108] = "FROMALTSTACK";
  OP2[OP2["2DROP"] = 109] = "2DROP";
  OP2[OP2["2DUP"] = 110] = "2DUP";
  OP2[OP2["3DUP"] = 111] = "3DUP";
  OP2[OP2["2OVER"] = 112] = "2OVER";
  OP2[OP2["2ROT"] = 113] = "2ROT";
  OP2[OP2["2SWAP"] = 114] = "2SWAP";
  OP2[OP2["IFDUP"] = 115] = "IFDUP";
  OP2[OP2["DEPTH"] = 116] = "DEPTH";
  OP2[OP2["DROP"] = 117] = "DROP";
  OP2[OP2["DUP"] = 118] = "DUP";
  OP2[OP2["NIP"] = 119] = "NIP";
  OP2[OP2["OVER"] = 120] = "OVER";
  OP2[OP2["PICK"] = 121] = "PICK";
  OP2[OP2["ROLL"] = 122] = "ROLL";
  OP2[OP2["ROT"] = 123] = "ROT";
  OP2[OP2["SWAP"] = 124] = "SWAP";
  OP2[OP2["TUCK"] = 125] = "TUCK";
  OP2[OP2["CAT"] = 126] = "CAT";
  OP2[OP2["SUBSTR"] = 127] = "SUBSTR";
  OP2[OP2["LEFT"] = 128] = "LEFT";
  OP2[OP2["RIGHT"] = 129] = "RIGHT";
  OP2[OP2["SIZE"] = 130] = "SIZE";
  OP2[OP2["INVERT"] = 131] = "INVERT";
  OP2[OP2["AND"] = 132] = "AND";
  OP2[OP2["OR"] = 133] = "OR";
  OP2[OP2["XOR"] = 134] = "XOR";
  OP2[OP2["EQUAL"] = 135] = "EQUAL";
  OP2[OP2["EQUALVERIFY"] = 136] = "EQUALVERIFY";
  OP2[OP2["RESERVED1"] = 137] = "RESERVED1";
  OP2[OP2["RESERVED2"] = 138] = "RESERVED2";
  OP2[OP2["1ADD"] = 139] = "1ADD";
  OP2[OP2["1SUB"] = 140] = "1SUB";
  OP2[OP2["2MUL"] = 141] = "2MUL";
  OP2[OP2["2DIV"] = 142] = "2DIV";
  OP2[OP2["NEGATE"] = 143] = "NEGATE";
  OP2[OP2["ABS"] = 144] = "ABS";
  OP2[OP2["NOT"] = 145] = "NOT";
  OP2[OP2["0NOTEQUAL"] = 146] = "0NOTEQUAL";
  OP2[OP2["ADD"] = 147] = "ADD";
  OP2[OP2["SUB"] = 148] = "SUB";
  OP2[OP2["MUL"] = 149] = "MUL";
  OP2[OP2["DIV"] = 150] = "DIV";
  OP2[OP2["MOD"] = 151] = "MOD";
  OP2[OP2["LSHIFT"] = 152] = "LSHIFT";
  OP2[OP2["RSHIFT"] = 153] = "RSHIFT";
  OP2[OP2["BOOLAND"] = 154] = "BOOLAND";
  OP2[OP2["BOOLOR"] = 155] = "BOOLOR";
  OP2[OP2["NUMEQUAL"] = 156] = "NUMEQUAL";
  OP2[OP2["NUMEQUALVERIFY"] = 157] = "NUMEQUALVERIFY";
  OP2[OP2["NUMNOTEQUAL"] = 158] = "NUMNOTEQUAL";
  OP2[OP2["LESSTHAN"] = 159] = "LESSTHAN";
  OP2[OP2["GREATERTHAN"] = 160] = "GREATERTHAN";
  OP2[OP2["LESSTHANOREQUAL"] = 161] = "LESSTHANOREQUAL";
  OP2[OP2["GREATERTHANOREQUAL"] = 162] = "GREATERTHANOREQUAL";
  OP2[OP2["MIN"] = 163] = "MIN";
  OP2[OP2["MAX"] = 164] = "MAX";
  OP2[OP2["WITHIN"] = 165] = "WITHIN";
  OP2[OP2["RIPEMD160"] = 166] = "RIPEMD160";
  OP2[OP2["SHA1"] = 167] = "SHA1";
  OP2[OP2["SHA256"] = 168] = "SHA256";
  OP2[OP2["HASH160"] = 169] = "HASH160";
  OP2[OP2["HASH256"] = 170] = "HASH256";
  OP2[OP2["CODESEPARATOR"] = 171] = "CODESEPARATOR";
  OP2[OP2["CHECKSIG"] = 172] = "CHECKSIG";
  OP2[OP2["CHECKSIGVERIFY"] = 173] = "CHECKSIGVERIFY";
  OP2[OP2["CHECKMULTISIG"] = 174] = "CHECKMULTISIG";
  OP2[OP2["CHECKMULTISIGVERIFY"] = 175] = "CHECKMULTISIGVERIFY";
  OP2[OP2["NOP1"] = 176] = "NOP1";
  OP2[OP2["CHECKLOCKTIMEVERIFY"] = 177] = "CHECKLOCKTIMEVERIFY";
  OP2[OP2["CHECKSEQUENCEVERIFY"] = 178] = "CHECKSEQUENCEVERIFY";
  OP2[OP2["NOP4"] = 179] = "NOP4";
  OP2[OP2["NOP5"] = 180] = "NOP5";
  OP2[OP2["NOP6"] = 181] = "NOP6";
  OP2[OP2["NOP7"] = 182] = "NOP7";
  OP2[OP2["NOP8"] = 183] = "NOP8";
  OP2[OP2["NOP9"] = 184] = "NOP9";
  OP2[OP2["NOP10"] = 185] = "NOP10";
  OP2[OP2["CHECKSIGADD"] = 186] = "CHECKSIGADD";
  OP2[OP2["INVALID"] = 255] = "INVALID";
})(OP || (OP = {}));
function ScriptNum(bytesLimit = 6, forceMinimal = false) {
  return wrap({
    encodeStream: (w, value) => {
      if (value === 0n)
        return;
      const neg = value < 0;
      const val = BigInt(value);
      const nums = [];
      for (let abs = neg ? -val : val;abs; abs >>= 8n)
        nums.push(Number(abs & 0xffn));
      if (nums[nums.length - 1] >= 128)
        nums.push(neg ? 128 : 0);
      else if (neg)
        nums[nums.length - 1] |= 128;
      w.bytes(new Uint8Array(nums));
    },
    decodeStream: (r) => {
      const len = r.leftBytes;
      if (len > bytesLimit)
        throw new Error(`ScriptNum: number (${len}) bigger than limit=${bytesLimit}`);
      if (len === 0)
        return 0n;
      if (forceMinimal) {
        const data = r.bytes(len, true);
        if ((data[data.length - 1] & 127) === 0) {
          if (len <= 1 || (data[data.length - 2] & 128) === 0)
            throw new Error("Non-minimally encoded ScriptNum");
        }
      }
      let last = 0;
      let res = 0n;
      for (let i = 0;i < len; ++i) {
        last = r.byte();
        res |= BigInt(last) << 8n * BigInt(i);
      }
      if (last >= 128) {
        res &= 2n ** BigInt(len * 8) - 1n >> 1n;
        res = -res;
      }
      return res;
    }
  });
}
function OpToNum(op, bytesLimit = 4, forceMinimal = true) {
  if (typeof op === "number")
    return op;
  if (isBytes5(op)) {
    try {
      const val = ScriptNum(bytesLimit, forceMinimal).decode(op);
      if (val > Number.MAX_SAFE_INTEGER)
        return;
      return Number(val);
    } catch (e) {
      return;
    }
  }
  return;
}
var Script = wrap({
  encodeStream: (w, value) => {
    for (let o of value) {
      if (typeof o === "string") {
        if (OP[o] === undefined)
          throw new Error(`Unknown opcode=${o}`);
        w.byte(OP[o]);
        continue;
      } else if (typeof o === "number") {
        if (o === 0) {
          w.byte(0);
          continue;
        } else if (1 <= o && o <= 16) {
          w.byte(OP.OP_1 - 1 + o);
          continue;
        }
      }
      if (typeof o === "number")
        o = ScriptNum().encode(BigInt(o));
      if (!isBytes5(o))
        throw new Error(`Wrong Script OP=${o} (${typeof o})`);
      const len = o.length;
      if (len < OP.PUSHDATA1)
        w.byte(len);
      else if (len <= 255) {
        w.byte(OP.PUSHDATA1);
        w.byte(len);
      } else if (len <= 65535) {
        w.byte(OP.PUSHDATA2);
        w.bytes(U16LE.encode(len));
      } else {
        w.byte(OP.PUSHDATA4);
        w.bytes(U32LE.encode(len));
      }
      w.bytes(o);
    }
  },
  decodeStream: (r) => {
    const out = [];
    while (!r.isEnd()) {
      const cur = r.byte();
      if (OP.OP_0 < cur && cur <= OP.PUSHDATA4) {
        let len;
        if (cur < OP.PUSHDATA1)
          len = cur;
        else if (cur === OP.PUSHDATA1)
          len = U8.decodeStream(r);
        else if (cur === OP.PUSHDATA2)
          len = U16LE.decodeStream(r);
        else if (cur === OP.PUSHDATA4)
          len = U32LE.decodeStream(r);
        else
          throw new Error("Should be not possible");
        out.push(r.bytes(len));
      } else if (cur === 0) {
        out.push(0);
      } else if (OP.OP_1 <= cur && cur <= OP.OP_16) {
        out.push(cur - (OP.OP_1 - 1));
      } else {
        const op = OP[cur];
        if (op === undefined)
          throw new Error(`Unknown opcode=${cur.toString(16)}`);
        out.push(op);
      }
    }
    return out;
  }
});
var CSLimits = {
  253: [253, 2, 253n, 65535n],
  254: [254, 4, 65536n, 4294967295n],
  255: [255, 8, 4294967296n, 18446744073709551615n]
};
var CompactSize = wrap({
  encodeStream: (w, value) => {
    if (typeof value === "number")
      value = BigInt(value);
    if (0n <= value && value <= 252n)
      return w.byte(Number(value));
    for (const [flag2, bytes, start, stop] of Object.values(CSLimits)) {
      if (start > value || value > stop)
        continue;
      w.byte(flag2);
      for (let i = 0;i < bytes; i++)
        w.byte(Number(value >> 8n * BigInt(i) & 0xffn));
      return;
    }
    throw w.err(`VarInt too big: ${value}`);
  },
  decodeStream: (r) => {
    const b0 = r.byte();
    if (b0 <= 252)
      return BigInt(b0);
    const [_, bytes, start] = CSLimits[b0];
    let num2 = 0n;
    for (let i = 0;i < bytes; i++)
      num2 |= BigInt(r.byte()) << 8n * BigInt(i);
    if (num2 < start)
      throw r.err(`Wrong CompactSize(${8 * bytes})`);
    return num2;
  }
});
var CompactSizeLen = apply(CompactSize, coders.numberBigint);
var VarBytes = createBytes(CompactSize);
var RawWitness = array(CompactSizeLen, VarBytes);
var BTCArray = (t) => array(CompactSize, t);
var RawInput = struct({
  txid: createBytes(32, true),
  index: U32LE,
  finalScriptSig: VarBytes,
  sequence: U32LE
});
var RawOutput = struct({ amount: U64LE, script: VarBytes });
var _RawTx = struct({
  version: I32LE,
  segwitFlag: flag(new Uint8Array([0, 1])),
  inputs: BTCArray(RawInput),
  outputs: BTCArray(RawOutput),
  witnesses: flagged("segwitFlag", array("inputs/length", RawWitness)),
  lockTime: U32LE
});
function validateRawTx(tx) {
  if (tx.segwitFlag && tx.witnesses && !tx.witnesses.length)
    throw new Error("Segwit flag with empty witnesses array");
  return tx;
}
var RawTx = validate(_RawTx, validateRawTx);
var RawOldTx = struct({
  version: I32LE,
  inputs: BTCArray(RawInput),
  outputs: BTCArray(RawOutput),
  lockTime: U32LE
});

// node_modules/@scure/btc-signer/esm/utxo.js
function getPrevOut(input) {
  if (input.nonWitnessUtxo) {
    if (input.index === undefined)
      throw new Error("Unknown input index");
    return input.nonWitnessUtxo.outputs[input.index];
  } else if (input.witnessUtxo)
    return input.witnessUtxo;
  else
    throw new Error("Cannot find previous output info");
}
function normalizeInput(i, cur, allowedFields, disableScriptCheck = false) {
  let { nonWitnessUtxo, txid } = i;
  if (typeof nonWitnessUtxo === "string")
    nonWitnessUtxo = hex.decode(nonWitnessUtxo);
  if (isBytes5(nonWitnessUtxo))
    nonWitnessUtxo = RawTx.decode(nonWitnessUtxo);
  if (!("nonWitnessUtxo" in i) && nonWitnessUtxo === undefined)
    nonWitnessUtxo = cur?.nonWitnessUtxo;
  if (typeof txid === "string")
    txid = hex.decode(txid);
  if (txid === undefined)
    txid = cur?.txid;
  let res = { ...cur, ...i, nonWitnessUtxo, txid };
  if (!("nonWitnessUtxo" in i) && res.nonWitnessUtxo === undefined)
    delete res.nonWitnessUtxo;
  if (res.sequence === undefined)
    res.sequence = DEFAULT_SEQUENCE;
  if (res.tapMerkleRoot === null)
    delete res.tapMerkleRoot;
  res = mergeKeyMap(PSBTInput, res, cur, allowedFields);
  PSBTInputCoder.encode(res);
  let prevOut;
  if (res.nonWitnessUtxo && res.index !== undefined)
    prevOut = res.nonWitnessUtxo.outputs[res.index];
  else if (res.witnessUtxo)
    prevOut = res.witnessUtxo;
  if (prevOut && !disableScriptCheck)
    checkScript(prevOut && prevOut.script, res.redeemScript, res.witnessScript);
  return res;
}
function getInputType(input, allowLegacyWitnessUtxo = false) {
  let txType = "legacy";
  let defaultSighash = SignatureHash.ALL;
  const prevOut = getPrevOut(input);
  const first = OutScript.decode(prevOut.script);
  let type = first.type;
  let cur = first;
  const stack = [first];
  if (first.type === "tr") {
    defaultSighash = SignatureHash.DEFAULT;
    return {
      txType: "taproot",
      type: "tr",
      last: first,
      lastScript: prevOut.script,
      defaultSighash,
      sighash: input.sighashType || defaultSighash
    };
  } else {
    if (first.type === "wpkh" || first.type === "wsh")
      txType = "segwit";
    if (first.type === "sh") {
      if (!input.redeemScript)
        throw new Error("inputType: sh without redeemScript");
      let child = OutScript.decode(input.redeemScript);
      if (child.type === "wpkh" || child.type === "wsh")
        txType = "segwit";
      stack.push(child);
      cur = child;
      type += `-${child.type}`;
    }
    if (cur.type === "wsh") {
      if (!input.witnessScript)
        throw new Error("inputType: wsh without witnessScript");
      let child = OutScript.decode(input.witnessScript);
      if (child.type === "wsh")
        txType = "segwit";
      stack.push(child);
      cur = child;
      type += `-${child.type}`;
    }
    const last = stack[stack.length - 1];
    if (last.type === "sh" || last.type === "wsh")
      throw new Error("inputType: sh/wsh cannot be terminal type");
    const lastScript = OutScript.encode(last);
    const res = {
      type,
      txType,
      last,
      lastScript,
      defaultSighash,
      sighash: input.sighashType || defaultSighash
    };
    if (txType === "legacy" && !allowLegacyWitnessUtxo && !input.nonWitnessUtxo) {
      throw new Error(`Transaction/sign: legacy input without nonWitnessUtxo, can result in attack that forces paying higher fees. Pass allowLegacyWitnessUtxo=true, if you sure`);
    }
    return res;
  }
}
var toVsize = (weight) => Math.ceil(weight / 4);

// node_modules/@scure/btc-signer/esm/transaction.js
var EMPTY32 = new Uint8Array(32);
var EMPTY_OUTPUT = {
  amount: 0xffffffffffffffffn,
  script: EMPTY
};
var PRECISION = 8;
var DEFAULT_VERSION = 2;
var DEFAULT_LOCKTIME = 0;
var DEFAULT_SEQUENCE = 4294967295;
var Decimal = coders.decimal(PRECISION);
var def = (value, def2) => value === undefined ? def2 : value;
function cloneDeep(obj) {
  if (Array.isArray(obj))
    return obj.map((i) => cloneDeep(i));
  else if (isBytes5(obj))
    return Uint8Array.from(obj);
  else if (["number", "bigint", "boolean", "string", "undefined"].includes(typeof obj))
    return obj;
  else if (obj === null)
    return obj;
  else if (typeof obj === "object") {
    return Object.fromEntries(Object.entries(obj).map(([k, v]) => [k, cloneDeep(v)]));
  }
  throw new Error(`cloneDeep: unknown type=${obj} (${typeof obj})`);
}
var SignatureHash;
(function(SignatureHash2) {
  SignatureHash2[SignatureHash2["DEFAULT"] = 0] = "DEFAULT";
  SignatureHash2[SignatureHash2["ALL"] = 1] = "ALL";
  SignatureHash2[SignatureHash2["NONE"] = 2] = "NONE";
  SignatureHash2[SignatureHash2["SINGLE"] = 3] = "SINGLE";
  SignatureHash2[SignatureHash2["ANYONECANPAY"] = 128] = "ANYONECANPAY";
})(SignatureHash || (SignatureHash = {}));
var SigHash;
(function(SigHash2) {
  SigHash2[SigHash2["DEFAULT"] = 0] = "DEFAULT";
  SigHash2[SigHash2["ALL"] = 1] = "ALL";
  SigHash2[SigHash2["NONE"] = 2] = "NONE";
  SigHash2[SigHash2["SINGLE"] = 3] = "SINGLE";
  SigHash2[SigHash2["DEFAULT_ANYONECANPAY"] = 128] = "DEFAULT_ANYONECANPAY";
  SigHash2[SigHash2["ALL_ANYONECANPAY"] = 129] = "ALL_ANYONECANPAY";
  SigHash2[SigHash2["NONE_ANYONECANPAY"] = 130] = "NONE_ANYONECANPAY";
  SigHash2[SigHash2["SINGLE_ANYONECANPAY"] = 131] = "SINGLE_ANYONECANPAY";
})(SigHash || (SigHash = {}));
function getTaprootKeys(privKey, pubKey, internalKey, merkleRoot = EMPTY) {
  if (equalBytes3(internalKey, pubKey)) {
    privKey = taprootTweakPrivKey(privKey, merkleRoot);
    pubKey = pubSchnorr(privKey);
  }
  return { privKey, pubKey };
}
function outputBeforeSign(i) {
  if (i.script === undefined || i.amount === undefined)
    throw new Error("Transaction/output: script and amount required");
  return { script: i.script, amount: i.amount };
}
function inputBeforeSign(i) {
  if (i.txid === undefined || i.index === undefined)
    throw new Error("Transaction/input: txid and index required");
  return {
    txid: i.txid,
    index: i.index,
    sequence: def(i.sequence, DEFAULT_SEQUENCE),
    finalScriptSig: def(i.finalScriptSig, EMPTY)
  };
}
function cleanFinalInput(i) {
  for (const _k in i) {
    const k = _k;
    if (!PSBTInputFinalKeys.includes(k))
      delete i[k];
  }
}
var TxHashIdx = struct({ txid: createBytes(32, true), index: U32LE });
function validateSigHash(s) {
  if (typeof s !== "number" || typeof SigHash[s] !== "string")
    throw new Error(`Invalid SigHash=${s}`);
  return s;
}
function unpackSighash(hashType) {
  const masked = hashType & 31;
  return {
    isAny: !!(hashType & SignatureHash.ANYONECANPAY),
    isNone: masked === SignatureHash.NONE,
    isSingle: masked === SignatureHash.SINGLE
  };
}
function validateOpts2(opts) {
  if (opts !== undefined && {}.toString.call(opts) !== "[object Object]")
    throw new Error(`Wrong object type for transaction options: ${opts}`);
  const _opts = {
    ...opts,
    version: def(opts.version, DEFAULT_VERSION),
    lockTime: def(opts.lockTime, 0),
    PSBTVersion: def(opts.PSBTVersion, 0)
  };
  if (typeof _opts.allowUnknowInput !== "undefined")
    opts.allowUnknownInputs = _opts.allowUnknowInput;
  if (typeof _opts.allowUnknowOutput !== "undefined")
    opts.allowUnknownOutputs = _opts.allowUnknowOutput;
  if (![-1, 0, 1, 2, 3].includes(_opts.version))
    throw new Error(`Unknown version: ${_opts.version}`);
  if (typeof _opts.lockTime !== "number")
    throw new Error("Transaction lock time should be number");
  U32LE.encode(_opts.lockTime);
  if (_opts.PSBTVersion !== 0 && _opts.PSBTVersion !== 2)
    throw new Error(`Unknown PSBT version ${_opts.PSBTVersion}`);
  for (const k of [
    "allowUnknownOutputs",
    "allowUnknownInputs",
    "disableScriptCheck",
    "bip174jsCompat",
    "allowLegacyWitnessUtxo",
    "lowR"
  ]) {
    const v = _opts[k];
    if (v === undefined)
      continue;
    if (typeof v !== "boolean")
      throw new Error(`Transation options wrong type: ${k}=${v} (${typeof v})`);
  }
  if (_opts.customScripts !== undefined) {
    const cs = _opts.customScripts;
    if (!Array.isArray(cs)) {
      throw new Error(`wrong custom scripts type (expected array): customScripts=${cs} (${typeof cs})`);
    }
    for (const s of cs) {
      if (typeof s.encode !== "function" || typeof s.decode !== "function")
        throw new Error(`wrong script=${s} (${typeof s})`);
      if (s.finalizeTaproot !== undefined && typeof s.finalizeTaproot !== "function")
        throw new Error(`wrong script=${s} (${typeof s})`);
    }
  }
  return Object.freeze(_opts);
}

class Transaction {
  constructor(opts = {}) {
    this.global = {};
    this.inputs = [];
    this.outputs = [];
    const _opts = this.opts = validateOpts2(opts);
    if (_opts.lockTime !== DEFAULT_LOCKTIME)
      this.global.fallbackLocktime = _opts.lockTime;
    this.global.txVersion = _opts.version;
  }
  static fromRaw(raw, opts = {}) {
    const parsed = RawTx.decode(raw);
    const tx = new Transaction({ ...opts, version: parsed.version, lockTime: parsed.lockTime });
    for (const o of parsed.outputs)
      tx.addOutput(o);
    tx.outputs = parsed.outputs;
    tx.inputs = parsed.inputs;
    if (parsed.witnesses) {
      for (let i = 0;i < parsed.witnesses.length; i++)
        tx.inputs[i].finalScriptWitness = parsed.witnesses[i];
    }
    return tx;
  }
  static fromPSBT(psbt_, opts = {}) {
    let parsed;
    try {
      parsed = RawPSBTV0.decode(psbt_);
    } catch (e0) {
      try {
        parsed = RawPSBTV2.decode(psbt_);
      } catch (e2) {
        throw e0;
      }
    }
    const PSBTVersion = parsed.global.version || 0;
    if (PSBTVersion !== 0 && PSBTVersion !== 2)
      throw new Error(`Wrong PSBT version=${PSBTVersion}`);
    const unsigned = parsed.global.unsignedTx;
    const version = PSBTVersion === 0 ? unsigned?.version : parsed.global.txVersion;
    const lockTime = PSBTVersion === 0 ? unsigned?.lockTime : parsed.global.fallbackLocktime;
    const tx = new Transaction({ ...opts, version, lockTime, PSBTVersion });
    const inputCount = PSBTVersion === 0 ? unsigned?.inputs.length : parsed.global.inputCount;
    tx.inputs = parsed.inputs.slice(0, inputCount).map((i, j) => ({
      finalScriptSig: EMPTY,
      ...parsed.global.unsignedTx?.inputs[j],
      ...i
    }));
    const outputCount = PSBTVersion === 0 ? unsigned?.outputs.length : parsed.global.outputCount;
    tx.outputs = parsed.outputs.slice(0, outputCount).map((i, j) => ({
      ...i,
      ...parsed.global.unsignedTx?.outputs[j]
    }));
    tx.global = { ...parsed.global, txVersion: version };
    if (lockTime !== DEFAULT_LOCKTIME)
      tx.global.fallbackLocktime = lockTime;
    return tx;
  }
  toPSBT(PSBTVersion = this.opts.PSBTVersion) {
    if (PSBTVersion !== 0 && PSBTVersion !== 2)
      throw new Error(`Wrong PSBT version=${PSBTVersion}`);
    const inputs = this.inputs.map((i) => cleanPSBTFields(PSBTVersion, PSBTInput, i));
    for (const inp of inputs) {
      if (inp.partialSig && !inp.partialSig.length)
        delete inp.partialSig;
      if (inp.finalScriptSig && !inp.finalScriptSig.length)
        delete inp.finalScriptSig;
      if (inp.finalScriptWitness && !inp.finalScriptWitness.length)
        delete inp.finalScriptWitness;
    }
    const outputs = this.outputs.map((i) => cleanPSBTFields(PSBTVersion, PSBTOutput, i));
    const global = { ...this.global };
    if (PSBTVersion === 0) {
      global.unsignedTx = RawOldTx.decode(RawOldTx.encode({
        version: this.version,
        lockTime: this.lockTime,
        inputs: this.inputs.map(inputBeforeSign).map((i) => ({
          ...i,
          finalScriptSig: EMPTY
        })),
        outputs: this.outputs.map(outputBeforeSign)
      }));
      delete global.fallbackLocktime;
      delete global.txVersion;
    } else {
      global.version = PSBTVersion;
      global.txVersion = this.version;
      global.inputCount = this.inputs.length;
      global.outputCount = this.outputs.length;
      if (global.fallbackLocktime && global.fallbackLocktime === DEFAULT_LOCKTIME)
        delete global.fallbackLocktime;
    }
    if (this.opts.bip174jsCompat) {
      if (!inputs.length)
        inputs.push({});
      if (!outputs.length)
        outputs.push({});
    }
    return (PSBTVersion === 0 ? RawPSBTV0 : RawPSBTV2).encode({
      global,
      inputs,
      outputs
    });
  }
  get lockTime() {
    let height = DEFAULT_LOCKTIME;
    let heightCnt = 0;
    let time = DEFAULT_LOCKTIME;
    let timeCnt = 0;
    for (const i of this.inputs) {
      if (i.requiredHeightLocktime) {
        height = Math.max(height, i.requiredHeightLocktime);
        heightCnt++;
      }
      if (i.requiredTimeLocktime) {
        time = Math.max(time, i.requiredTimeLocktime);
        timeCnt++;
      }
    }
    if (heightCnt && heightCnt >= timeCnt)
      return height;
    if (time !== DEFAULT_LOCKTIME)
      return time;
    return this.global.fallbackLocktime || DEFAULT_LOCKTIME;
  }
  get version() {
    if (this.global.txVersion === undefined)
      throw new Error("No global.txVersion");
    return this.global.txVersion;
  }
  inputStatus(idx) {
    this.checkInputIdx(idx);
    const input = this.inputs[idx];
    if (input.finalScriptSig && input.finalScriptSig.length)
      return "finalized";
    if (input.finalScriptWitness && input.finalScriptWitness.length)
      return "finalized";
    if (input.tapKeySig)
      return "signed";
    if (input.tapScriptSig && input.tapScriptSig.length)
      return "signed";
    if (input.partialSig && input.partialSig.length)
      return "signed";
    return "unsigned";
  }
  inputSighash(idx) {
    this.checkInputIdx(idx);
    const inputSighash = this.inputs[idx].sighashType;
    const sighash = inputSighash === undefined ? SignatureHash.DEFAULT : inputSighash;
    const sigOutputs = sighash === SignatureHash.DEFAULT ? SignatureHash.ALL : sighash & 3;
    const sigInputs = sighash & SignatureHash.ANYONECANPAY;
    return { sigInputs, sigOutputs };
  }
  signStatus() {
    let addInput = true, addOutput = true;
    let inputs = [], outputs = [];
    for (let idx = 0;idx < this.inputs.length; idx++) {
      const status = this.inputStatus(idx);
      if (status === "unsigned")
        continue;
      const { sigInputs, sigOutputs } = this.inputSighash(idx);
      if (sigInputs === SignatureHash.ANYONECANPAY)
        inputs.push(idx);
      else
        addInput = false;
      if (sigOutputs === SignatureHash.ALL)
        addOutput = false;
      else if (sigOutputs === SignatureHash.SINGLE)
        outputs.push(idx);
      else if (sigOutputs === SignatureHash.NONE) {} else
        throw new Error(`Wrong signature hash output type: ${sigOutputs}`);
    }
    return { addInput, addOutput, inputs, outputs };
  }
  get isFinal() {
    for (let idx = 0;idx < this.inputs.length; idx++)
      if (this.inputStatus(idx) !== "finalized")
        return false;
    return true;
  }
  get hasWitnesses() {
    let out = false;
    for (const i of this.inputs)
      if (i.finalScriptWitness && i.finalScriptWitness.length)
        out = true;
    return out;
  }
  get weight() {
    if (!this.isFinal)
      throw new Error("Transaction is not finalized");
    let out = 32;
    const outputs = this.outputs.map(outputBeforeSign);
    out += 4 * CompactSizeLen.encode(this.outputs.length).length;
    for (const o of outputs)
      out += 32 + 4 * VarBytes.encode(o.script).length;
    if (this.hasWitnesses)
      out += 2;
    out += 4 * CompactSizeLen.encode(this.inputs.length).length;
    for (const i of this.inputs) {
      out += 160 + 4 * VarBytes.encode(i.finalScriptSig || EMPTY).length;
      if (this.hasWitnesses && i.finalScriptWitness)
        out += RawWitness.encode(i.finalScriptWitness).length;
    }
    return out;
  }
  get vsize() {
    return toVsize(this.weight);
  }
  toBytes(withScriptSig = false, withWitness = false) {
    return RawTx.encode({
      version: this.version,
      lockTime: this.lockTime,
      inputs: this.inputs.map(inputBeforeSign).map((i) => ({
        ...i,
        finalScriptSig: withScriptSig && i.finalScriptSig || EMPTY
      })),
      outputs: this.outputs.map(outputBeforeSign),
      witnesses: this.inputs.map((i) => i.finalScriptWitness || []),
      segwitFlag: withWitness && this.hasWitnesses
    });
  }
  get unsignedTx() {
    return this.toBytes(false, false);
  }
  get hex() {
    return hex.encode(this.toBytes(true, this.hasWitnesses));
  }
  get hash() {
    if (!this.isFinal)
      throw new Error("Transaction is not finalized");
    return hex.encode(sha256x2(this.toBytes(true)));
  }
  get id() {
    if (!this.isFinal)
      throw new Error("Transaction is not finalized");
    return hex.encode(sha256x2(this.toBytes(true)).reverse());
  }
  checkInputIdx(idx) {
    if (!Number.isSafeInteger(idx) || 0 > idx || idx >= this.inputs.length)
      throw new Error(`Wrong input index=${idx}`);
  }
  getInput(idx) {
    this.checkInputIdx(idx);
    return cloneDeep(this.inputs[idx]);
  }
  get inputsLength() {
    return this.inputs.length;
  }
  addInput(input, _ignoreSignStatus = false) {
    if (!_ignoreSignStatus && !this.signStatus().addInput)
      throw new Error("Tx has signed inputs, cannot add new one");
    this.inputs.push(normalizeInput(input, undefined, undefined, this.opts.disableScriptCheck));
    return this.inputs.length - 1;
  }
  updateInput(idx, input, _ignoreSignStatus = false) {
    this.checkInputIdx(idx);
    let allowedFields = undefined;
    if (!_ignoreSignStatus) {
      const status = this.signStatus();
      if (!status.addInput || status.inputs.includes(idx))
        allowedFields = PSBTInputUnsignedKeys;
    }
    this.inputs[idx] = normalizeInput(input, this.inputs[idx], allowedFields, this.opts.disableScriptCheck);
  }
  checkOutputIdx(idx) {
    if (!Number.isSafeInteger(idx) || 0 > idx || idx >= this.outputs.length)
      throw new Error(`Wrong output index=${idx}`);
  }
  getOutput(idx) {
    this.checkOutputIdx(idx);
    return cloneDeep(this.outputs[idx]);
  }
  getOutputAddress(idx, network = NETWORK) {
    const out = this.getOutput(idx);
    if (!out.script)
      return;
    return Address(network).encode(OutScript.decode(out.script));
  }
  get outputsLength() {
    return this.outputs.length;
  }
  normalizeOutput(o, cur, allowedFields) {
    let { amount, script } = o;
    if (amount === undefined)
      amount = cur?.amount;
    if (typeof amount !== "bigint")
      throw new Error(`Wrong amount type, should be of type bigint in sats, but got ${amount} of type ${typeof amount}`);
    if (typeof script === "string")
      script = hex.decode(script);
    if (script === undefined)
      script = cur?.script;
    let res = { ...cur, ...o, amount, script };
    if (res.amount === undefined)
      delete res.amount;
    res = mergeKeyMap(PSBTOutput, res, cur, allowedFields);
    PSBTOutputCoder.encode(res);
    if (res.script && !this.opts.allowUnknownOutputs && OutScript.decode(res.script).type === "unknown") {
      throw new Error("Transaction/output: unknown output script type, there is a chance that input is unspendable. Pass allowUnknownOutputs=true, if you sure");
    }
    if (!this.opts.disableScriptCheck)
      checkScript(res.script, res.redeemScript, res.witnessScript);
    return res;
  }
  addOutput(o, _ignoreSignStatus = false) {
    if (!_ignoreSignStatus && !this.signStatus().addOutput)
      throw new Error("Tx has signed outputs, cannot add new one");
    this.outputs.push(this.normalizeOutput(o));
    return this.outputs.length - 1;
  }
  updateOutput(idx, output, _ignoreSignStatus = false) {
    this.checkOutputIdx(idx);
    let allowedFields = undefined;
    if (!_ignoreSignStatus) {
      const status = this.signStatus();
      if (!status.addOutput || status.outputs.includes(idx))
        allowedFields = PSBTOutputUnsignedKeys;
    }
    this.outputs[idx] = this.normalizeOutput(output, this.outputs[idx], allowedFields);
  }
  addOutputAddress(address, amount, network = NETWORK) {
    return this.addOutput({ script: OutScript.encode(Address(network).decode(address)), amount });
  }
  get fee() {
    let res = 0n;
    for (const i of this.inputs) {
      const prevOut = getPrevOut(i);
      if (!prevOut)
        throw new Error("Empty input amount");
      res += prevOut.amount;
    }
    const outputs = this.outputs.map(outputBeforeSign);
    for (const o of outputs)
      res -= o.amount;
    return res;
  }
  preimageLegacy(idx, prevOutScript, hashType) {
    const { isAny, isNone, isSingle } = unpackSighash(hashType);
    if (idx < 0 || !Number.isSafeInteger(idx))
      throw new Error(`Invalid input idx=${idx}`);
    if (isSingle && idx >= this.outputs.length || idx >= this.inputs.length)
      return U256BE.encode(1n);
    prevOutScript = Script.encode(Script.decode(prevOutScript).filter((i) => i !== "CODESEPARATOR"));
    let inputs = this.inputs.map(inputBeforeSign).map((input, inputIdx) => ({
      ...input,
      finalScriptSig: inputIdx === idx ? prevOutScript : EMPTY
    }));
    if (isAny)
      inputs = [inputs[idx]];
    else if (isNone || isSingle) {
      inputs = inputs.map((input, inputIdx) => ({
        ...input,
        sequence: inputIdx === idx ? input.sequence : 0
      }));
    }
    let outputs = this.outputs.map(outputBeforeSign);
    if (isNone)
      outputs = [];
    else if (isSingle) {
      outputs = outputs.slice(0, idx).fill(EMPTY_OUTPUT).concat([outputs[idx]]);
    }
    const tmpTx = RawTx.encode({
      lockTime: this.lockTime,
      version: this.version,
      segwitFlag: false,
      inputs,
      outputs
    });
    return sha256x2(tmpTx, I32LE.encode(hashType));
  }
  preimageWitnessV0(idx, prevOutScript, hashType, amount) {
    const { isAny, isNone, isSingle } = unpackSighash(hashType);
    let inputHash = EMPTY32;
    let sequenceHash = EMPTY32;
    let outputHash = EMPTY32;
    const inputs = this.inputs.map(inputBeforeSign);
    const outputs = this.outputs.map(outputBeforeSign);
    if (!isAny)
      inputHash = sha256x2(...inputs.map(TxHashIdx.encode));
    if (!isAny && !isSingle && !isNone)
      sequenceHash = sha256x2(...inputs.map((i) => U32LE.encode(i.sequence)));
    if (!isSingle && !isNone) {
      outputHash = sha256x2(...outputs.map(RawOutput.encode));
    } else if (isSingle && idx < outputs.length)
      outputHash = sha256x2(RawOutput.encode(outputs[idx]));
    const input = inputs[idx];
    return sha256x2(I32LE.encode(this.version), inputHash, sequenceHash, createBytes(32, true).encode(input.txid), U32LE.encode(input.index), VarBytes.encode(prevOutScript), U64LE.encode(amount), U32LE.encode(input.sequence), outputHash, U32LE.encode(this.lockTime), U32LE.encode(hashType));
  }
  preimageWitnessV1(idx, prevOutScript, hashType, amount, codeSeparator = -1, leafScript, leafVer = 192, annex) {
    if (!Array.isArray(amount) || this.inputs.length !== amount.length)
      throw new Error(`Invalid amounts array=${amount}`);
    if (!Array.isArray(prevOutScript) || this.inputs.length !== prevOutScript.length)
      throw new Error(`Invalid prevOutScript array=${prevOutScript}`);
    const out = [
      U8.encode(0),
      U8.encode(hashType),
      I32LE.encode(this.version),
      U32LE.encode(this.lockTime)
    ];
    const outType = hashType === SignatureHash.DEFAULT ? SignatureHash.ALL : hashType & 3;
    const inType = hashType & SignatureHash.ANYONECANPAY;
    const inputs = this.inputs.map(inputBeforeSign);
    const outputs = this.outputs.map(outputBeforeSign);
    if (inType !== SignatureHash.ANYONECANPAY) {
      out.push(...[
        inputs.map(TxHashIdx.encode),
        amount.map(U64LE.encode),
        prevOutScript.map(VarBytes.encode),
        inputs.map((i) => U32LE.encode(i.sequence))
      ].map((i) => sha256(concatBytes4(...i))));
    }
    if (outType === SignatureHash.ALL) {
      out.push(sha256(concatBytes4(...outputs.map(RawOutput.encode))));
    }
    const spendType = (annex ? 1 : 0) | (leafScript ? 2 : 0);
    out.push(new Uint8Array([spendType]));
    if (inType === SignatureHash.ANYONECANPAY) {
      const inp = inputs[idx];
      out.push(TxHashIdx.encode(inp), U64LE.encode(amount[idx]), VarBytes.encode(prevOutScript[idx]), U32LE.encode(inp.sequence));
    } else
      out.push(U32LE.encode(idx));
    if (spendType & 1)
      out.push(sha256(VarBytes.encode(annex || EMPTY)));
    if (outType === SignatureHash.SINGLE)
      out.push(idx < outputs.length ? sha256(RawOutput.encode(outputs[idx])) : EMPTY32);
    if (leafScript)
      out.push(tapLeafHash(leafScript, leafVer), U8.encode(0), I32LE.encode(codeSeparator));
    return tagSchnorr("TapSighash", ...out);
  }
  signIdx(privateKey, idx, allowedSighash, _auxRand) {
    this.checkInputIdx(idx);
    const input = this.inputs[idx];
    const inputType = getInputType(input, this.opts.allowLegacyWitnessUtxo);
    if (!isBytes5(privateKey)) {
      if (!input.bip32Derivation || !input.bip32Derivation.length)
        throw new Error("bip32Derivation: empty");
      const signers = input.bip32Derivation.filter((i) => i[1].fingerprint == privateKey.fingerprint).map(([pubKey, { path }]) => {
        let s = privateKey;
        for (const i of path)
          s = s.deriveChild(i);
        if (!equalBytes3(s.publicKey, pubKey))
          throw new Error("bip32Derivation: wrong pubKey");
        if (!s.privateKey)
          throw new Error("bip32Derivation: no privateKey");
        return s;
      });
      if (!signers.length)
        throw new Error(`bip32Derivation: no items with fingerprint=${privateKey.fingerprint}`);
      let signed = false;
      for (const s of signers)
        if (this.signIdx(s.privateKey, idx))
          signed = true;
      return signed;
    }
    if (!allowedSighash)
      allowedSighash = [inputType.defaultSighash];
    else
      allowedSighash.forEach(validateSigHash);
    const sighash = inputType.sighash;
    if (!allowedSighash.includes(sighash)) {
      throw new Error(`Input with not allowed sigHash=${sighash}. Allowed: ${allowedSighash.join(", ")}`);
    }
    const { sigOutputs } = this.inputSighash(idx);
    if (sigOutputs === SignatureHash.SINGLE && idx >= this.outputs.length) {
      throw new Error(`Input with sighash SINGLE, but there is no output with corresponding index=${idx}`);
    }
    const prevOut = getPrevOut(input);
    if (inputType.txType === "taproot") {
      const prevOuts = this.inputs.map(getPrevOut);
      const prevOutScript = prevOuts.map((i) => i.script);
      const amount = prevOuts.map((i) => i.amount);
      let signed = false;
      let schnorrPub = pubSchnorr(privateKey);
      let merkleRoot = input.tapMerkleRoot || EMPTY;
      if (input.tapInternalKey) {
        const { pubKey, privKey } = getTaprootKeys(privateKey, schnorrPub, input.tapInternalKey, merkleRoot);
        const [taprootPubKey, _] = taprootTweakPubkey(input.tapInternalKey, merkleRoot);
        if (equalBytes3(taprootPubKey, pubKey)) {
          const hash = this.preimageWitnessV1(idx, prevOutScript, sighash, amount);
          const sig = concatBytes4(signSchnorr(hash, privKey, _auxRand), sighash !== SignatureHash.DEFAULT ? new Uint8Array([sighash]) : EMPTY);
          this.updateInput(idx, { tapKeySig: sig }, true);
          signed = true;
        }
      }
      if (input.tapLeafScript) {
        input.tapScriptSig = input.tapScriptSig || [];
        for (const [_, _script] of input.tapLeafScript) {
          const script = _script.subarray(0, -1);
          const scriptDecoded = Script.decode(script);
          const ver = _script[_script.length - 1];
          const hash = tapLeafHash(script, ver);
          const pos = scriptDecoded.findIndex((i) => isBytes5(i) && equalBytes3(i, schnorrPub));
          if (pos === -1)
            continue;
          const msg = this.preimageWitnessV1(idx, prevOutScript, sighash, amount, undefined, script, ver);
          const sig = concatBytes4(signSchnorr(msg, privateKey, _auxRand), sighash !== SignatureHash.DEFAULT ? new Uint8Array([sighash]) : EMPTY);
          this.updateInput(idx, { tapScriptSig: [[{ pubKey: schnorrPub, leafHash: hash }, sig]] }, true);
          signed = true;
        }
      }
      if (!signed)
        throw new Error("No taproot scripts signed");
      return true;
    } else {
      const pubKey = pubECDSA(privateKey);
      let hasPubkey = false;
      const pubKeyHash = hash160(pubKey);
      for (const i of Script.decode(inputType.lastScript)) {
        if (isBytes5(i) && (equalBytes3(i, pubKey) || equalBytes3(i, pubKeyHash)))
          hasPubkey = true;
      }
      if (!hasPubkey)
        throw new Error(`Input script doesn't have pubKey: ${inputType.lastScript}`);
      let hash;
      if (inputType.txType === "legacy") {
        hash = this.preimageLegacy(idx, inputType.lastScript, sighash);
      } else if (inputType.txType === "segwit") {
        let script = inputType.lastScript;
        if (inputType.last.type === "wpkh")
          script = OutScript.encode({ type: "pkh", hash: inputType.last.hash });
        hash = this.preimageWitnessV0(idx, script, sighash, prevOut.amount);
      } else
        throw new Error(`Transaction/sign: unknown tx type: ${inputType.txType}`);
      const sig = signECDSA(hash, privateKey, this.opts.lowR);
      this.updateInput(idx, {
        partialSig: [[pubKey, concatBytes4(sig, new Uint8Array([sighash]))]]
      }, true);
    }
    return true;
  }
  sign(privateKey, allowedSighash, _auxRand) {
    let num2 = 0;
    for (let i = 0;i < this.inputs.length; i++) {
      try {
        if (this.signIdx(privateKey, i, allowedSighash, _auxRand))
          num2++;
      } catch (e) {}
    }
    if (!num2)
      throw new Error("No inputs signed");
    return num2;
  }
  finalizeIdx(idx) {
    this.checkInputIdx(idx);
    if (this.fee < 0n)
      throw new Error("Outputs spends more than inputs amount");
    const input = this.inputs[idx];
    const inputType = getInputType(input, this.opts.allowLegacyWitnessUtxo);
    if (inputType.txType === "taproot") {
      if (input.tapKeySig)
        input.finalScriptWitness = [input.tapKeySig];
      else if (input.tapLeafScript && input.tapScriptSig) {
        const leafs = input.tapLeafScript.sort((a, b) => TaprootControlBlock.encode(a[0]).length - TaprootControlBlock.encode(b[0]).length);
        for (const [cb, _script] of leafs) {
          const script = _script.slice(0, -1);
          const ver = _script[_script.length - 1];
          const outScript = OutScript.decode(script);
          const hash = tapLeafHash(script, ver);
          const scriptSig = input.tapScriptSig.filter((i) => equalBytes3(i[0].leafHash, hash));
          let signatures = [];
          if (outScript.type === "tr_ms") {
            const m = outScript.m;
            const pubkeys = outScript.pubkeys;
            let added = 0;
            for (const pub of pubkeys) {
              const sigIdx = scriptSig.findIndex((i) => equalBytes3(i[0].pubKey, pub));
              if (added === m || sigIdx === -1) {
                signatures.push(EMPTY);
                continue;
              }
              signatures.push(scriptSig[sigIdx][1]);
              added++;
            }
            if (added !== m)
              continue;
          } else if (outScript.type === "tr_ns") {
            for (const pub of outScript.pubkeys) {
              const sigIdx = scriptSig.findIndex((i) => equalBytes3(i[0].pubKey, pub));
              if (sigIdx === -1)
                continue;
              signatures.push(scriptSig[sigIdx][1]);
            }
            if (signatures.length !== outScript.pubkeys.length)
              continue;
          } else if (outScript.type === "unknown" && this.opts.allowUnknownInputs) {
            const scriptDecoded = Script.decode(script);
            signatures = scriptSig.map(([{ pubKey }, signature]) => {
              const pos = scriptDecoded.findIndex((i) => isBytes5(i) && equalBytes3(i, pubKey));
              if (pos === -1)
                throw new Error("finalize/taproot: cannot find position of pubkey in script");
              return { signature, pos };
            }).sort((a, b) => a.pos - b.pos).map((i) => i.signature);
            if (!signatures.length)
              continue;
          } else {
            const custom = this.opts.customScripts;
            if (custom) {
              for (const c of custom) {
                if (!c.finalizeTaproot)
                  continue;
                const scriptDecoded = Script.decode(script);
                const csEncoded = c.encode(scriptDecoded);
                if (csEncoded === undefined)
                  continue;
                const finalized = c.finalizeTaproot(script, csEncoded, scriptSig);
                if (!finalized)
                  continue;
                input.finalScriptWitness = finalized.concat(TaprootControlBlock.encode(cb));
                input.finalScriptSig = EMPTY;
                cleanFinalInput(input);
                return;
              }
            }
            throw new Error("Finalize: Unknown tapLeafScript");
          }
          input.finalScriptWitness = signatures.reverse().concat([script, TaprootControlBlock.encode(cb)]);
          break;
        }
        if (!input.finalScriptWitness)
          throw new Error("finalize/taproot: empty witness");
      } else
        throw new Error("finalize/taproot: unknown input");
      input.finalScriptSig = EMPTY;
      cleanFinalInput(input);
      return;
    }
    if (!input.partialSig || !input.partialSig.length)
      throw new Error("Not enough partial sign");
    let inputScript = EMPTY;
    let witness = [];
    if (inputType.last.type === "ms") {
      const m = inputType.last.m;
      const pubkeys = inputType.last.pubkeys;
      let signatures = [];
      for (const pub of pubkeys) {
        const sign = input.partialSig.find((s) => equalBytes3(pub, s[0]));
        if (!sign)
          continue;
        signatures.push(sign[1]);
      }
      signatures = signatures.slice(0, m);
      if (signatures.length !== m) {
        throw new Error(`Multisig: wrong signatures count, m=${m} n=${pubkeys.length} signatures=${signatures.length}`);
      }
      inputScript = Script.encode([0, ...signatures]);
    } else if (inputType.last.type === "pk") {
      inputScript = Script.encode([input.partialSig[0][1]]);
    } else if (inputType.last.type === "pkh") {
      inputScript = Script.encode([input.partialSig[0][1], input.partialSig[0][0]]);
    } else if (inputType.last.type === "wpkh") {
      inputScript = EMPTY;
      witness = [input.partialSig[0][1], input.partialSig[0][0]];
    } else if (inputType.last.type === "unknown" && !this.opts.allowUnknownInputs)
      throw new Error("Unknown inputs not allowed");
    let finalScriptSig, finalScriptWitness;
    if (inputType.type.includes("wsh-")) {
      if (inputScript.length && inputType.lastScript.length) {
        witness = Script.decode(inputScript).map((i) => {
          if (i === 0)
            return EMPTY;
          if (isBytes5(i))
            return i;
          throw new Error(`Wrong witness op=${i}`);
        });
      }
      witness = witness.concat(inputType.lastScript);
    }
    if (inputType.txType === "segwit")
      finalScriptWitness = witness;
    if (inputType.type.startsWith("sh-wsh-")) {
      finalScriptSig = Script.encode([Script.encode([0, sha256(inputType.lastScript)])]);
    } else if (inputType.type.startsWith("sh-")) {
      finalScriptSig = Script.encode([...Script.decode(inputScript), inputType.lastScript]);
    } else if (inputType.type.startsWith("wsh-")) {} else if (inputType.txType !== "segwit")
      finalScriptSig = inputScript;
    if (!finalScriptSig && !finalScriptWitness)
      throw new Error("Unknown error finalizing input");
    if (finalScriptSig)
      input.finalScriptSig = finalScriptSig;
    if (finalScriptWitness)
      input.finalScriptWitness = finalScriptWitness;
    cleanFinalInput(input);
  }
  finalize() {
    for (let i = 0;i < this.inputs.length; i++)
      this.finalizeIdx(i);
  }
  extract() {
    if (!this.isFinal)
      throw new Error("Transaction has unfinalized inputs");
    if (!this.outputs.length)
      throw new Error("Transaction has no outputs");
    if (this.fee < 0n)
      throw new Error("Outputs spends more than inputs amount");
    return this.toBytes(true, true);
  }
  combine(other) {
    for (const k of ["PSBTVersion", "version", "lockTime"]) {
      if (this.opts[k] !== other.opts[k]) {
        throw new Error(`Transaction/combine: different ${k} this=${this.opts[k]} other=${other.opts[k]}`);
      }
    }
    for (const k of ["inputs", "outputs"]) {
      if (this[k].length !== other[k].length) {
        throw new Error(`Transaction/combine: different ${k} length this=${this[k].length} other=${other[k].length}`);
      }
    }
    const thisUnsigned = this.global.unsignedTx ? RawOldTx.encode(this.global.unsignedTx) : EMPTY;
    const otherUnsigned = other.global.unsignedTx ? RawOldTx.encode(other.global.unsignedTx) : EMPTY;
    if (!equalBytes3(thisUnsigned, otherUnsigned))
      throw new Error(`Transaction/combine: different unsigned tx`);
    this.global = mergeKeyMap(PSBTGlobal, this.global, other.global);
    for (let i = 0;i < this.inputs.length; i++)
      this.updateInput(i, other.inputs[i], true);
    for (let i = 0;i < this.outputs.length; i++)
      this.updateOutput(i, other.outputs[i], true);
    return this;
  }
  clone() {
    return Transaction.fromPSBT(this.toPSBT(this.opts.PSBTVersion), this.opts);
  }
}

// node_modules/@scure/btc-signer/esm/psbt.js
var PubKeyECDSA = validate(createBytes(null), (pub) => validatePubkey(pub, PubT.ecdsa));
var PubKeySchnorr = validate(createBytes(32), (pub) => validatePubkey(pub, PubT.schnorr));
var SignatureSchnorr = validate(createBytes(null), (sig) => {
  if (sig.length !== 64 && sig.length !== 65)
    throw new Error("Schnorr signature should be 64 or 65 bytes long");
  return sig;
});
var BIP32Der = struct({
  fingerprint: U32BE,
  path: array(null, U32LE)
});
var TaprootBIP32Der = struct({
  hashes: array(CompactSizeLen, createBytes(32)),
  der: BIP32Der
});
var GlobalXPUB = createBytes(78);
var tapScriptSigKey = struct({ pubKey: PubKeySchnorr, leafHash: createBytes(32) });
var _TaprootControlBlock = struct({
  version: U8,
  internalKey: createBytes(32),
  merklePath: array(null, createBytes(32))
});
var TaprootControlBlock = validate(_TaprootControlBlock, (cb) => {
  if (cb.merklePath.length > 128)
    throw new Error("TaprootControlBlock: merklePath should be of length 0..128 (inclusive)");
  return cb;
});
var tapTree = array(null, struct({
  depth: U8,
  version: U8,
  script: VarBytes
}));
var BytesInf = createBytes(null);
var Bytes20 = createBytes(20);
var Bytes32 = createBytes(32);
var PSBTGlobal = {
  unsignedTx: [0, false, RawOldTx, [0], [0], false],
  xpub: [1, GlobalXPUB, BIP32Der, [], [0, 2], false],
  txVersion: [2, false, U32LE, [2], [2], false],
  fallbackLocktime: [3, false, U32LE, [], [2], false],
  inputCount: [4, false, CompactSizeLen, [2], [2], false],
  outputCount: [5, false, CompactSizeLen, [2], [2], false],
  txModifiable: [6, false, U8, [], [2], false],
  version: [251, false, U32LE, [], [0, 2], false],
  proprietary: [252, BytesInf, BytesInf, [], [0, 2], false]
};
var PSBTInput = {
  nonWitnessUtxo: [0, false, RawTx, [], [0, 2], false],
  witnessUtxo: [1, false, RawOutput, [], [0, 2], false],
  partialSig: [2, PubKeyECDSA, BytesInf, [], [0, 2], false],
  sighashType: [3, false, U32LE, [], [0, 2], false],
  redeemScript: [4, false, BytesInf, [], [0, 2], false],
  witnessScript: [5, false, BytesInf, [], [0, 2], false],
  bip32Derivation: [6, PubKeyECDSA, BIP32Der, [], [0, 2], false],
  finalScriptSig: [7, false, BytesInf, [], [0, 2], false],
  finalScriptWitness: [8, false, RawWitness, [], [0, 2], false],
  porCommitment: [9, false, BytesInf, [], [0, 2], false],
  ripemd160: [10, Bytes20, BytesInf, [], [0, 2], false],
  sha256: [11, Bytes32, BytesInf, [], [0, 2], false],
  hash160: [12, Bytes20, BytesInf, [], [0, 2], false],
  hash256: [13, Bytes32, BytesInf, [], [0, 2], false],
  txid: [14, false, Bytes32, [2], [2], true],
  index: [15, false, U32LE, [2], [2], true],
  sequence: [16, false, U32LE, [], [2], true],
  requiredTimeLocktime: [17, false, U32LE, [], [2], false],
  requiredHeightLocktime: [18, false, U32LE, [], [2], false],
  tapKeySig: [19, false, SignatureSchnorr, [], [0, 2], false],
  tapScriptSig: [20, tapScriptSigKey, SignatureSchnorr, [], [0, 2], false],
  tapLeafScript: [21, TaprootControlBlock, BytesInf, [], [0, 2], false],
  tapBip32Derivation: [22, Bytes32, TaprootBIP32Der, [], [0, 2], false],
  tapInternalKey: [23, false, PubKeySchnorr, [], [0, 2], false],
  tapMerkleRoot: [24, false, Bytes32, [], [0, 2], false],
  proprietary: [252, BytesInf, BytesInf, [], [0, 2], false]
};
var PSBTInputFinalKeys = [
  "txid",
  "sequence",
  "index",
  "witnessUtxo",
  "nonWitnessUtxo",
  "finalScriptSig",
  "finalScriptWitness",
  "unknown"
];
var PSBTInputUnsignedKeys = [
  "partialSig",
  "finalScriptSig",
  "finalScriptWitness",
  "tapKeySig",
  "tapScriptSig"
];
var PSBTOutput = {
  redeemScript: [0, false, BytesInf, [], [0, 2], false],
  witnessScript: [1, false, BytesInf, [], [0, 2], false],
  bip32Derivation: [2, PubKeyECDSA, BIP32Der, [], [0, 2], false],
  amount: [3, false, I64LE, [2], [2], true],
  script: [4, false, BytesInf, [2], [2], true],
  tapInternalKey: [5, false, PubKeySchnorr, [], [0, 2], false],
  tapTree: [6, false, tapTree, [], [0, 2], false],
  tapBip32Derivation: [7, PubKeySchnorr, TaprootBIP32Der, [], [0, 2], false],
  proprietary: [252, BytesInf, BytesInf, [], [0, 2], false]
};
var PSBTOutputUnsignedKeys = [];
var PSBTKeyPair = array(NULL, struct({
  key: prefix(CompactSizeLen, struct({ type: CompactSizeLen, key: createBytes(null) })),
  value: createBytes(CompactSizeLen)
}));
function PSBTKeyInfo(info) {
  const [type, kc, vc, reqInc, allowInc, silentIgnore] = info;
  return { type, kc, vc, reqInc, allowInc, silentIgnore };
}
var PSBTUnknownKey = struct({ type: CompactSizeLen, key: createBytes(null) });
function PSBTKeyMap(psbtEnum) {
  const byType = {};
  for (const k in psbtEnum) {
    const [num2, kc, vc] = psbtEnum[k];
    byType[num2] = [k, kc, vc];
  }
  return wrap({
    encodeStream: (w, value) => {
      let out = [];
      for (const name in psbtEnum) {
        const val = value[name];
        if (val === undefined)
          continue;
        const [type, kc, vc] = psbtEnum[name];
        if (!kc) {
          out.push({ key: { type, key: EMPTY }, value: vc.encode(val) });
        } else {
          const kv = val.map(([k, v]) => [
            kc.encode(k),
            vc.encode(v)
          ]);
          kv.sort((a, b) => compareBytes(a[0], b[0]));
          for (const [key, value2] of kv)
            out.push({ key: { key, type }, value: value2 });
        }
      }
      if (value.unknown) {
        value.unknown.sort((a, b) => compareBytes(a[0].key, b[0].key));
        for (const [k, v] of value.unknown)
          out.push({ key: k, value: v });
      }
      PSBTKeyPair.encodeStream(w, out);
    },
    decodeStream: (r) => {
      const raw = PSBTKeyPair.decodeStream(r);
      const out = {};
      const noKey = {};
      for (const elm of raw) {
        let name = "unknown";
        let key = elm.key.key;
        let value = elm.value;
        if (byType[elm.key.type]) {
          const [_name, kc, vc] = byType[elm.key.type];
          name = _name;
          if (!kc && key.length) {
            throw new Error(`PSBT: Non-empty key for ${name} (key=${hex.encode(key)} value=${hex.encode(value)}`);
          }
          key = kc ? kc.decode(key) : undefined;
          value = vc.decode(value);
          if (!kc) {
            if (out[name])
              throw new Error(`PSBT: Same keys: ${name} (key=${key} value=${value})`);
            out[name] = value;
            noKey[name] = true;
            continue;
          }
        } else {
          key = { type: elm.key.type, key: elm.key.key };
        }
        if (noKey[name])
          throw new Error(`PSBT: Key type with empty key and no key=${name} val=${value}`);
        if (!out[name])
          out[name] = [];
        out[name].push([key, value]);
      }
      return out;
    }
  });
}
var PSBTInputCoder = validate(PSBTKeyMap(PSBTInput), (i) => {
  if (i.finalScriptWitness && !i.finalScriptWitness.length)
    throw new Error("validateInput: empty finalScriptWitness");
  if (i.partialSig && !i.partialSig.length)
    throw new Error("Empty partialSig");
  if (i.partialSig)
    for (const [k] of i.partialSig)
      validatePubkey(k, PubT.ecdsa);
  if (i.bip32Derivation)
    for (const [k] of i.bip32Derivation)
      validatePubkey(k, PubT.ecdsa);
  if (i.requiredTimeLocktime !== undefined && i.requiredTimeLocktime < 500000000)
    throw new Error(`validateInput: wrong timeLocktime=${i.requiredTimeLocktime}`);
  if (i.requiredHeightLocktime !== undefined && (i.requiredHeightLocktime <= 0 || i.requiredHeightLocktime >= 500000000))
    throw new Error(`validateInput: wrong heighLocktime=${i.requiredHeightLocktime}`);
  if (i.nonWitnessUtxo && i.index !== undefined) {
    const last = i.nonWitnessUtxo.outputs.length - 1;
    if (i.index > last)
      throw new Error(`validateInput: index(${i.index}) not in nonWitnessUtxo`);
    const prevOut = i.nonWitnessUtxo.outputs[i.index];
    if (i.witnessUtxo && (!equalBytes3(i.witnessUtxo.script, prevOut.script) || i.witnessUtxo.amount !== prevOut.amount))
      throw new Error("validateInput: witnessUtxo different from nonWitnessUtxo");
  }
  if (i.tapLeafScript) {
    for (const [k, v] of i.tapLeafScript) {
      if ((k.version & 254) !== v[v.length - 1])
        throw new Error("validateInput: tapLeafScript version mimatch");
      if (v[v.length - 1] & 1)
        throw new Error("validateInput: tapLeafScript version has parity bit!");
    }
  }
  if (i.nonWitnessUtxo && i.index !== undefined && i.txid) {
    const outputs = i.nonWitnessUtxo.outputs;
    if (outputs.length - 1 < i.index)
      throw new Error("nonWitnessUtxo: incorect output index");
    const tx = Transaction.fromRaw(RawTx.encode(i.nonWitnessUtxo), {
      allowUnknownOutputs: true,
      disableScriptCheck: true,
      allowUnknownInputs: true
    });
    const txid = hex.encode(i.txid);
    if (tx.isFinal && tx.id !== txid)
      throw new Error(`nonWitnessUtxo: wrong txid, exp=${txid} got=${tx.id}`);
  }
  return i;
});
var PSBTOutputCoder = validate(PSBTKeyMap(PSBTOutput), (o) => {
  if (o.bip32Derivation)
    for (const [k] of o.bip32Derivation)
      validatePubkey(k, PubT.ecdsa);
  return o;
});
var PSBTGlobalCoder = validate(PSBTKeyMap(PSBTGlobal), (g) => {
  const version = g.version || 0;
  if (version === 0) {
    if (!g.unsignedTx)
      throw new Error("PSBTv0: missing unsignedTx");
    for (const inp of g.unsignedTx.inputs)
      if (inp.finalScriptSig && inp.finalScriptSig.length)
        throw new Error("PSBTv0: input scriptSig found in unsignedTx");
  }
  return g;
});
var _RawPSBTV0 = struct({
  magic: magic(string(new Uint8Array([255])), "psbt"),
  global: PSBTGlobalCoder,
  inputs: array("global/unsignedTx/inputs/length", PSBTInputCoder),
  outputs: array(null, PSBTOutputCoder)
});
var _RawPSBTV2 = struct({
  magic: magic(string(new Uint8Array([255])), "psbt"),
  global: PSBTGlobalCoder,
  inputs: array("global/inputCount", PSBTInputCoder),
  outputs: array("global/outputCount", PSBTOutputCoder)
});
var _DebugPSBT = struct({
  magic: magic(string(new Uint8Array([255])), "psbt"),
  items: array(null, apply(array(NULL, tuple([createHex(CompactSizeLen), createBytes(CompactSize)])), coders.dict()))
});
function validatePSBTFields(version, info, lst) {
  for (const k in lst) {
    if (k === "unknown")
      continue;
    if (!info[k])
      continue;
    const { allowInc } = PSBTKeyInfo(info[k]);
    if (!allowInc.includes(version))
      throw new Error(`PSBTv${version}: field ${k} is not allowed`);
  }
  for (const k in info) {
    const { reqInc } = PSBTKeyInfo(info[k]);
    if (reqInc.includes(version) && lst[k] === undefined)
      throw new Error(`PSBTv${version}: missing required field ${k}`);
  }
}
function cleanPSBTFields(version, info, lst) {
  const out = {};
  for (const _k in lst) {
    const k = _k;
    if (k !== "unknown") {
      if (!info[k])
        continue;
      const { allowInc, silentIgnore } = PSBTKeyInfo(info[k]);
      if (!allowInc.includes(version)) {
        if (silentIgnore)
          continue;
        throw new Error(`Failed to serialize in PSBTv${version}: ${k} but versions allows inclusion=${allowInc}`);
      }
    }
    out[k] = lst[k];
  }
  return out;
}
function validatePSBT(tx) {
  const version = tx && tx.global && tx.global.version || 0;
  validatePSBTFields(version, PSBTGlobal, tx.global);
  for (const i of tx.inputs)
    validatePSBTFields(version, PSBTInput, i);
  for (const o of tx.outputs)
    validatePSBTFields(version, PSBTOutput, o);
  const inputCount = !version ? tx.global.unsignedTx.inputs.length : tx.global.inputCount;
  if (tx.inputs.length < inputCount)
    throw new Error("Not enough inputs");
  const inputsLeft = tx.inputs.slice(inputCount);
  if (inputsLeft.length > 1 || inputsLeft.length && Object.keys(inputsLeft[0]).length)
    throw new Error(`Unexpected inputs left in tx=${inputsLeft}`);
  const outputCount = !version ? tx.global.unsignedTx.outputs.length : tx.global.outputCount;
  if (tx.outputs.length < outputCount)
    throw new Error("Not outputs inputs");
  const outputsLeft = tx.outputs.slice(outputCount);
  if (outputsLeft.length > 1 || outputsLeft.length && Object.keys(outputsLeft[0]).length)
    throw new Error(`Unexpected outputs left in tx=${outputsLeft}`);
  return tx;
}
function mergeKeyMap(psbtEnum, val, cur, allowedFields) {
  const res = { ...cur, ...val };
  for (const k in psbtEnum) {
    const key = k;
    const [_, kC, vC] = psbtEnum[key];
    const cannotChange = allowedFields && !allowedFields.includes(k);
    if (val[k] === undefined && k in val) {
      if (cannotChange)
        throw new Error(`Cannot remove signed field=${k}`);
      delete res[k];
    } else if (kC) {
      const oldKV = cur && cur[k] ? cur[k] : [];
      let newKV = val[key];
      if (newKV) {
        if (!Array.isArray(newKV))
          throw new Error(`keyMap(${k}): KV pairs should be [k, v][]`);
        newKV = newKV.map((val2) => {
          if (val2.length !== 2)
            throw new Error(`keyMap(${k}): KV pairs should be [k, v][]`);
          return [
            typeof val2[0] === "string" ? kC.decode(hex.decode(val2[0])) : val2[0],
            typeof val2[1] === "string" ? vC.decode(hex.decode(val2[1])) : val2[1]
          ];
        });
        const map = {};
        const add = (kStr, k2, v) => {
          if (map[kStr] === undefined) {
            map[kStr] = [k2, v];
            return;
          }
          const oldVal = hex.encode(vC.encode(map[kStr][1]));
          const newVal = hex.encode(vC.encode(v));
          if (oldVal !== newVal)
            throw new Error(`keyMap(${key}): same key=${kStr} oldVal=${oldVal} newVal=${newVal}`);
        };
        for (const [k2, v] of oldKV) {
          const kStr = hex.encode(kC.encode(k2));
          add(kStr, k2, v);
        }
        for (const [k2, v] of newKV) {
          const kStr = hex.encode(kC.encode(k2));
          if (v === undefined) {
            if (cannotChange)
              throw new Error(`Cannot remove signed field=${key}/${k2}`);
            delete map[kStr];
          } else
            add(kStr, k2, v);
        }
        res[key] = Object.values(map);
      }
    } else if (typeof res[k] === "string") {
      res[k] = vC.decode(hex.decode(res[k]));
    } else if (cannotChange && k in val && cur && cur[k] !== undefined) {
      if (!equalBytes3(vC.encode(val[k]), vC.encode(cur[k])))
        throw new Error(`Cannot change signed field=${k}`);
    }
  }
  for (const k in res)
    if (!psbtEnum[k])
      delete res[k];
  return res;
}
var RawPSBTV0 = validate(_RawPSBTV0, validatePSBT);
var RawPSBTV2 = validate(_RawPSBTV2, validatePSBT);

// node_modules/@scure/btc-signer/esm/payment.js
var OutP2A = {
  encode(from) {
    if (from.length !== 2 || from[0] !== 1 || !isBytes5(from[1]) || hex.encode(from[1]) !== "4e73")
      return;
    return { type: "p2a", script: Script.encode(from) };
  },
  decode: (to) => {
    if (to.type !== "p2a")
      return;
    return [1, hex.decode("4e73")];
  }
};
function isValidPubkey(pub, type) {
  try {
    validatePubkey(pub, type);
    return true;
  } catch (e) {
    return false;
  }
}
var OutPK = {
  encode(from) {
    if (from.length !== 2 || !isBytes5(from[0]) || !isValidPubkey(from[0], PubT.ecdsa) || from[1] !== "CHECKSIG")
      return;
    return { type: "pk", pubkey: from[0] };
  },
  decode: (to) => to.type === "pk" ? [to.pubkey, "CHECKSIG"] : undefined
};
var OutPKH = {
  encode(from) {
    if (from.length !== 5 || from[0] !== "DUP" || from[1] !== "HASH160" || !isBytes5(from[2]))
      return;
    if (from[3] !== "EQUALVERIFY" || from[4] !== "CHECKSIG")
      return;
    return { type: "pkh", hash: from[2] };
  },
  decode: (to) => to.type === "pkh" ? ["DUP", "HASH160", to.hash, "EQUALVERIFY", "CHECKSIG"] : undefined
};
var OutSH = {
  encode(from) {
    if (from.length !== 3 || from[0] !== "HASH160" || !isBytes5(from[1]) || from[2] !== "EQUAL")
      return;
    return { type: "sh", hash: from[1] };
  },
  decode: (to) => to.type === "sh" ? ["HASH160", to.hash, "EQUAL"] : undefined
};
var OutWSH = {
  encode(from) {
    if (from.length !== 2 || from[0] !== 0 || !isBytes5(from[1]))
      return;
    if (from[1].length !== 32)
      return;
    return { type: "wsh", hash: from[1] };
  },
  decode: (to) => to.type === "wsh" ? [0, to.hash] : undefined
};
var OutWPKH = {
  encode(from) {
    if (from.length !== 2 || from[0] !== 0 || !isBytes5(from[1]))
      return;
    if (from[1].length !== 20)
      return;
    return { type: "wpkh", hash: from[1] };
  },
  decode: (to) => to.type === "wpkh" ? [0, to.hash] : undefined
};
var OutMS = {
  encode(from) {
    const last = from.length - 1;
    if (from[last] !== "CHECKMULTISIG")
      return;
    const m = from[0];
    const n = from[last - 1];
    if (typeof m !== "number" || typeof n !== "number")
      return;
    const pubkeys = from.slice(1, -2);
    if (n !== pubkeys.length)
      return;
    for (const pub of pubkeys)
      if (!isBytes5(pub))
        return;
    return { type: "ms", m, pubkeys };
  },
  decode: (to) => to.type === "ms" ? [to.m, ...to.pubkeys, to.pubkeys.length, "CHECKMULTISIG"] : undefined
};
var OutTR = {
  encode(from) {
    if (from.length !== 2 || from[0] !== 1 || !isBytes5(from[1]))
      return;
    return { type: "tr", pubkey: from[1] };
  },
  decode: (to) => to.type === "tr" ? [1, to.pubkey] : undefined
};
var OutTRNS = {
  encode(from) {
    const last = from.length - 1;
    if (from[last] !== "CHECKSIG")
      return;
    const pubkeys = [];
    for (let i = 0;i < last; i++) {
      const elm = from[i];
      if (i & 1) {
        if (elm !== "CHECKSIGVERIFY" || i === last - 1)
          return;
        continue;
      }
      if (!isBytes5(elm))
        return;
      pubkeys.push(elm);
    }
    return { type: "tr_ns", pubkeys };
  },
  decode: (to) => {
    if (to.type !== "tr_ns")
      return;
    const out = [];
    for (let i = 0;i < to.pubkeys.length - 1; i++)
      out.push(to.pubkeys[i], "CHECKSIGVERIFY");
    out.push(to.pubkeys[to.pubkeys.length - 1], "CHECKSIG");
    return out;
  }
};
var OutTRMS = {
  encode(from) {
    const last = from.length - 1;
    if (from[last] !== "NUMEQUAL" || from[1] !== "CHECKSIG")
      return;
    const pubkeys = [];
    const m = OpToNum(from[last - 1]);
    if (typeof m !== "number")
      return;
    for (let i = 0;i < last - 1; i++) {
      const elm = from[i];
      if (i & 1) {
        if (elm !== (i === 1 ? "CHECKSIG" : "CHECKSIGADD"))
          throw new Error("OutScript.encode/tr_ms: wrong element");
        continue;
      }
      if (!isBytes5(elm))
        throw new Error("OutScript.encode/tr_ms: wrong key element");
      pubkeys.push(elm);
    }
    return { type: "tr_ms", pubkeys, m };
  },
  decode: (to) => {
    if (to.type !== "tr_ms")
      return;
    const out = [to.pubkeys[0], "CHECKSIG"];
    for (let i = 1;i < to.pubkeys.length; i++)
      out.push(to.pubkeys[i], "CHECKSIGADD");
    out.push(to.m, "NUMEQUAL");
    return out;
  }
};
var OutUnknown = {
  encode(from) {
    return { type: "unknown", script: Script.encode(from) };
  },
  decode: (to) => to.type === "unknown" ? Script.decode(to.script) : undefined
};
var OutScripts = [
  OutP2A,
  OutPK,
  OutPKH,
  OutSH,
  OutWSH,
  OutWPKH,
  OutMS,
  OutTR,
  OutTRNS,
  OutTRMS,
  OutUnknown
];
var _OutScript = apply(Script, coders.match(OutScripts));
var OutScript = validate(_OutScript, (i) => {
  if (i.type === "pk" && !isValidPubkey(i.pubkey, PubT.ecdsa))
    throw new Error("OutScript/pk: wrong key");
  if ((i.type === "pkh" || i.type === "sh" || i.type === "wpkh") && (!isBytes5(i.hash) || i.hash.length !== 20))
    throw new Error(`OutScript/${i.type}: wrong hash`);
  if (i.type === "wsh" && (!isBytes5(i.hash) || i.hash.length !== 32))
    throw new Error(`OutScript/wsh: wrong hash`);
  if (i.type === "tr" && (!isBytes5(i.pubkey) || !isValidPubkey(i.pubkey, PubT.schnorr)))
    throw new Error("OutScript/tr: wrong taproot public key");
  if (i.type === "ms" || i.type === "tr_ns" || i.type === "tr_ms") {
    if (!Array.isArray(i.pubkeys))
      throw new Error("OutScript/multisig: wrong pubkeys array");
  }
  if (i.type === "ms") {
    const n = i.pubkeys.length;
    for (const p of i.pubkeys)
      if (!isValidPubkey(p, PubT.ecdsa))
        throw new Error("OutScript/multisig: wrong pubkey");
    if (i.m <= 0 || n > 16 || i.m > n)
      throw new Error("OutScript/multisig: invalid params");
  }
  if (i.type === "tr_ns" || i.type === "tr_ms") {
    for (const p of i.pubkeys)
      if (!isValidPubkey(p, PubT.schnorr))
        throw new Error(`OutScript/${i.type}: wrong pubkey`);
  }
  if (i.type === "tr_ms") {
    const n = i.pubkeys.length;
    if (i.m <= 0 || n > 999 || i.m > n)
      throw new Error("OutScript/tr_ms: invalid params");
  }
  return i;
});
function checkWSH(s, witnessScript) {
  if (!equalBytes3(s.hash, sha256(witnessScript)))
    throw new Error("checkScript: wsh wrong witnessScript hash");
  const w = OutScript.decode(witnessScript);
  if (w.type === "tr" || w.type === "tr_ns" || w.type === "tr_ms")
    throw new Error(`checkScript: P2${w.type} cannot be wrapped in P2SH`);
  if (w.type === "wpkh" || w.type === "sh")
    throw new Error(`checkScript: P2${w.type} cannot be wrapped in P2WSH`);
}
function checkScript(script, redeemScript, witnessScript) {
  if (script) {
    const s = OutScript.decode(script);
    if (s.type === "tr_ns" || s.type === "tr_ms" || s.type === "ms" || s.type == "pk")
      throw new Error(`checkScript: non-wrapped ${s.type}`);
    if (s.type === "sh" && redeemScript) {
      if (!equalBytes3(s.hash, hash160(redeemScript)))
        throw new Error("checkScript: sh wrong redeemScript hash");
      const r = OutScript.decode(redeemScript);
      if (r.type === "tr" || r.type === "tr_ns" || r.type === "tr_ms")
        throw new Error(`checkScript: P2${r.type} cannot be wrapped in P2SH`);
      if (r.type === "sh")
        throw new Error("checkScript: P2SH cannot be wrapped in P2SH");
    }
    if (s.type === "wsh" && witnessScript)
      checkWSH(s, witnessScript);
  }
  if (redeemScript) {
    const r = OutScript.decode(redeemScript);
    if (r.type === "wsh" && witnessScript)
      checkWSH(r, witnessScript);
  }
}
var TAP_LEAF_VERSION = 192;
var tapLeafHash = (script, version = TAP_LEAF_VERSION) => tagSchnorr("TapLeaf", new Uint8Array([version]), VarBytes.encode(script));
var base58check = createBase58check(sha256);
function validateWitness(version, data) {
  if (data.length < 2 || data.length > 40)
    throw new Error("Witness: invalid length");
  if (version > 16)
    throw new Error("Witness: invalid version");
  if (version === 0 && !(data.length === 20 || data.length === 32))
    throw new Error("Witness: invalid length for version");
}
function programToWitness(version, data, network = NETWORK) {
  validateWitness(version, data);
  const coder = version === 0 ? bech32 : bech32m;
  return coder.encode(network.bech32, [version].concat(coder.toWords(data)));
}
function formatKey(hashed, prefix2) {
  return base58check.encode(concatBytes4(Uint8Array.from(prefix2), hashed));
}
function Address(network = NETWORK) {
  return {
    encode(from) {
      const { type } = from;
      if (type === "wpkh")
        return programToWitness(0, from.hash, network);
      else if (type === "wsh")
        return programToWitness(0, from.hash, network);
      else if (type === "tr")
        return programToWitness(1, from.pubkey, network);
      else if (type === "pkh")
        return formatKey(from.hash, [network.pubKeyHash]);
      else if (type === "sh")
        return formatKey(from.hash, [network.scriptHash]);
      throw new Error(`Unknown address type=${type}`);
    },
    decode(address) {
      if (address.length < 14 || address.length > 74)
        throw new Error("Invalid address length");
      if (network.bech32 && address.toLowerCase().startsWith(`${network.bech32}1`)) {
        let res;
        try {
          res = bech32.decode(address);
          if (res.words[0] !== 0)
            throw new Error(`bech32: wrong version=${res.words[0]}`);
        } catch (_) {
          res = bech32m.decode(address);
          if (res.words[0] === 0)
            throw new Error(`bech32m: wrong version=${res.words[0]}`);
        }
        if (res.prefix !== network.bech32)
          throw new Error(`wrong bech32 prefix=${res.prefix}`);
        const [version, ...program] = res.words;
        const data2 = bech32.fromWords(program);
        validateWitness(version, data2);
        if (version === 0 && data2.length === 32)
          return { type: "wsh", hash: data2 };
        else if (version === 0 && data2.length === 20)
          return { type: "wpkh", hash: data2 };
        else if (version === 1 && data2.length === 32)
          return { type: "tr", pubkey: data2 };
        else
          throw new Error("Unknown witness program");
      }
      const data = base58check.decode(address);
      if (data.length !== 21)
        throw new Error("Invalid base58 address");
      if (data[0] === network.pubKeyHash) {
        return { type: "pkh", hash: data.slice(1) };
      } else if (data[0] === network.scriptHash) {
        return {
          type: "sh",
          hash: data.slice(1)
        };
      }
      throw new Error(`Invalid address prefix=${data[0]}`);
    }
  };
}
// node_modules/@scure/btc-signer/esm/index.js
/*! scure-btc-signer - MIT License (c) 2022 Paul Miller (paulmillr.com) */
export {
  Transaction,
  TEST_NETWORK,
  SigHash,
  OutScript,
  NETWORK,
  Address
};
