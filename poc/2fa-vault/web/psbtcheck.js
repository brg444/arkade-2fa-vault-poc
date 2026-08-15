import { schnorr, sha256 } from "./vendor/secp256k1.js";
import {
  Address,
  OutScript,
  SigHash,
  TEST_NETWORK,
  Transaction,
} from "./vendor/btc-signer.js";

export const PSBT_OPTS = Object.freeze({
  allowUnknownInputs: true,
  allowUnknownOutputs: true,
});

export const DUST_SATS = 330n;
export const PACKET_TYPE = 0x01;
export const ARK_MAGIC = new Uint8Array([0x41, 0x52, 0x4b]);
const REGTEST = Object.freeze({ ...TEST_NETWORK, bech32: "bcrt" });

export function bytesToHex(b) {
  return [...toBytes(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(h) {
  if (typeof h !== "string" || h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) {
    throw new Error("hex");
  }
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToB64(bytes) {
  let s = "";
  for (const x of toBytes(bytes)) s += String.fromCharCode(x);
  return btoa(s);
}

export function bytesEqual(a, b) {
  const x = toBytes(a);
  const y = toBytes(b);
  if (x.length !== y.length) return false;
  let d = 0;
  for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
  return d === 0;
}

export function parsePSBT(b64) {
  if (typeof b64 !== "string" || b64.length === 0) throw new Error("psbt required");
  return Transaction.fromPSBT(b64ToBytes(b64), PSBT_OPTS);
}

export function scriptFromAddress(addr) {
  if (!addr) throw new Error("operational address required");
  return OutScript.encode(Address(REGTEST).decode(addr));
}

export function snapshotPSBT(tx) {
  if (!(tx instanceof Transaction)) throw new Error("psbt snapshot requires parsed transaction");
  const inputs = [];
  for (let i = 0; i < tx.inputsLength; i++) inputs.push(normalize(tx.getInput(i)));
  const outputs = [];
  for (let i = 0; i < tx.outputsLength; i++) outputs.push(normalize(tx.getOutput(i)));
  return {
    version: tx.version,
    lockTime: tx.lockTime,
    inputs,
    outputs,
  };
}

export function assertDirectP256(derivedHex, persistedHex, statusHex) {
  const derived = requireHex(derivedHex, "derived direct P-256");
  if (requireHex(persistedHex, "persisted direct P-256") !== derived) {
    throw new Error("derived DirectP256 does not match local record");
  }
  if (requireHex(statusHex, "status direct P-256") !== derived) {
    throw new Error("derived DirectP256 does not match vault status");
  }
  return derived;
}

export function assertHotPub(derivedHex, persistedHex, statusHex) {
  const derived = requireHex(derivedHex, "derived hot pub");
  if (persistedHex && requireHex(persistedHex, "persisted hot pub") !== derived) {
    throw new Error("derived hot pub does not match persisted hot pub");
  }
  if (statusHex && requireHex(statusHex, "status hot pub") !== derived) {
    throw new Error("derived hot pub does not match vault status hot pub");
  }
  return derived;
}

export function validateDraftPSBT(args) {
  return inspectPSBT({ ...args, b64: args.draftB64, expectEmptyWitness: true });
}

export function validateBoundPSBT(args) {
  const draftTx = parsePSBT(args.draftB64);
  const boundTx = parsePSBT(args.boundB64);
  const draftSnap = snapshotPSBT(draftTx);
  const bound = inspectPSBT({
    ...args,
    tx: boundTx,
    b64: args.boundB64,
    expectEmptyWitness: false,
  });
  const draft = inspectPSBT({
    ...args,
    tx: draftTx,
    b64: args.draftB64,
    expectEmptyWitness: true,
  });
  assertDraftBoundEqual(draftSnap, snapshotPSBT(boundTx), bound.packetIndex);
  if (draft.packet.script !== bound.packet.script) {
    throw new Error("bind mutated authorization script");
  }
  if (draft.packet.vin !== bound.packet.vin) {
    throw new Error("bind mutated packet vin");
  }
  const wantWitness = expectedDirectWitness(args.directSig);
  if (bound.packet.witness.length !== wantWitness.length) {
    throw new Error("bound packet witness count");
  }
  for (let i = 0; i < wantWitness.length; i++) {
    if (bound.packet.witness[i] !== bytesToHex(wantWitness[i])) {
      throw new Error("bound packet witness does not match direct signature");
    }
  }
  return bound;
}

export function reviewFields(parsed) {
  return {
    source: parsed.source,
    prevout: parsed.prevout,
    inputValue: parsed.inputValue,
    recipientScript: parsed.recipientScript,
    recipientAmount: parsed.recipientAmount,
    changeScript: parsed.changeScript,
    changeAmount: parsed.changeAmount,
    fee: parsed.fee,
    sighash: parsed.sighash,
    leafScript: parsed.leafScript,
    controlBlock: parsed.controlBlock,
    packetVin: parsed.packet.vin,
    packetWitnessItems: parsed.packet.witness.length,
  };
}

export function validateAuthorizedPSBT(args) {
  if (!args || !args.submittedB64 || !args.authorizedB64) {
    throw new Error("submitted and authorized psbts required");
  }
  const submitted = parsePSBT(args.submittedB64);
  const authorized = parsePSBT(args.authorizedB64);
  if (JSON.stringify(stripSigs(snapshotPSBT(submitted))) !== JSON.stringify(stripSigs(snapshotPSBT(authorized)))) {
    throw new Error("authorize mutated non-signature psbt fields");
  }
  const before = tapSigs(submitted.getInput(0));
  const after = tapSigs(authorized.getInput(0));
  if (before.length !== 1) throw new Error("submitted psbt must carry the hot signature only");
  if (after.length !== 2) throw new Error("authorized psbt must add exactly one provider signature");
  const hot = before[0];
  if (args.hotPubHex) {
    const wantHot = requireHex(args.hotPubHex, "hot pub").slice(2);
    if (hot.pub !== wantHot) throw new Error("submitted hot signature key");
  }
  const extras = after.filter((s) => s.pub !== hot.pub || s.sig !== hot.sig || s.leaf !== hot.leaf);
  if (extras.length !== 1) throw new Error("authorized provider signature delta");
  const extra = extras[0];
  if (extra.pub === hot.pub) throw new Error("provider signature reuses the hot key");
  if (extra.leaf !== hot.leaf) throw new Error("provider signature leaf");
  if (extra.sig.length !== 128) throw new Error("provider signature must be 64 bytes");
  const authInput = authorized.getInput(0);
  if (!authInput.witnessUtxo) throw new Error("authorized witness utxo required");
  if (!authInput.tapLeafScript || authInput.tapLeafScript.length !== 1) {
    throw new Error("authorized tap leaf required");
  }
  const leafBytes = toBytes(authInput.tapLeafScript[0][1]);
  if (leafBytes.length < 2) throw new Error("tap leaf");
  const script = leafBytes.subarray(0, -1);
  const ver = leafBytes[leafBytes.length - 1];
  const msg = authorized.preimageWitnessV1(
    0,
    [authInput.witnessUtxo.script],
    authInput.sighashType ?? SigHash.DEFAULT,
    [authInput.witnessUtxo.amount],
    undefined,
    script,
    ver,
  );
  if (!schnorr.verify(hexToBytes(extra.sig), msg, hexToBytes(extra.pub))) {
    throw new Error("provider signature invalid");
  }
  return { providerPub: extra.pub };
}

function tapSigs(input) {
  return (input.tapScriptSig || []).map(normalizeTapSig);
}

function normalizeTapSig(entry) {
  const meta = entry[0];
  const sig = toBytes(entry[1]);
  const raw = sig.length === 65 ? sig.slice(0, 64) : sig;
  return {
    pub: bytesToHex(toBytes(meta.pubKey)),
    leaf: bytesToHex(toBytes(meta.leafHash)),
    sig: bytesToHex(raw),
  };
}

export function hotSignPSBT(b64, priv) {
  const tx = parsePSBT(b64);
  const before = snapshotPSBT(tx);
  tx.sign(toBytes(priv));
  const signed = tx.toPSBT();
  const after = snapshotPSBT(Transaction.fromPSBT(signed, PSBT_OPTS));
  if (JSON.stringify(stripSigs(before)) !== JSON.stringify(stripSigs(after))) {
    throw new Error("local sign mutated non-signature psbt fields");
  }
  return bytesToB64(signed);
}

function inspectPSBT(args) {
  const tx = args.tx || parsePSBT(args.b64);
  if (tx.version !== 2) throw new Error("transaction version must be 2");
  if (tx.lockTime !== 0) throw new Error("locktime must be zero");
  if (tx.inputsLength !== 1) throw new Error("exactly one input required");
  if (tx.outputsLength < 2) throw new Error("recipient and packet outputs required");
  const input = tx.getInput(0);
  if (input.sequence !== 0xffffffff) {
    throw new Error("collaborative sequence must be final");
  }
  if (input.sighashType !== SigHash.DEFAULT) {
    throw new Error("sighash must be SIGHASH_DEFAULT");
  }
  if (!input.witnessUtxo) throw new Error("witness utxo required");
  if (!input.tapLeafScript || input.tapLeafScript.length !== 1) {
    throw new Error("exactly one collaborative tap leaf required");
  }
  const prevRaw = hexToBytes(args.prevTxHex);
  const prev = Transaction.fromRaw(prevRaw, PSBT_OPTS);
  if (input.index !== Number(args.vout)) throw new Error("prevout vout mismatch");
  if (!bytesEqual(input.txid, sha256d(prev.toBytes(true, false)))) {
    throw new Error("prevout txid mismatch");
  }
  const prevOut = prev.getOutput(Number(args.vout));
  if (!prevOut) throw new Error("prevout vout out of range");
  if (input.witnessUtxo.amount !== prevOut.amount) {
    throw new Error("witness utxo amount does not match prevout");
  }
  if (!bytesEqual(input.witnessUtxo.script, prevOut.script)) {
    throw new Error("witness utxo script does not match prevout");
  }
  const operational = operationalScript(args);
  if (!bytesEqual(input.witnessUtxo.script, operational)) {
    throw new Error("input is not the operational vault");
  }

  let recipient = null;
  let change = null;
  let packet = null;
  let packetIndex = -1;
  for (let i = 0; i < tx.outputsLength; i++) {
    const out = tx.getOutput(i);
    const script = toBytes(out.script);
    if (isExtensionScript(script)) {
      if (packet) throw new Error("multiple extension outputs");
      if (out.amount !== 0n) throw new Error("extension output must be zero value");
      packet = parseCanonicalPacket(script, args.expectEmptyWitness);
      packetIndex = i;
      continue;
    }
    if (bytesEqual(script, operational)) {
      if (change) throw new Error("multiple change outputs");
      if (out.amount < DUST_SATS) throw new Error("change below dust");
      change = { script, amount: out.amount };
      continue;
    }
    if (recipient) throw new Error("multiple recipient outputs");
    if (script.length === 0 || script[0] === 0x6a) throw new Error("unexpected op_return or unspendable output");
    if (out.amount < DUST_SATS) throw new Error("recipient below dust");
    recipient = { script, amount: out.amount };
  }
  if (!recipient) throw new Error("missing recipient");
  if (!packet) throw new Error("missing emulator packet output");

  const wantRecipient = hexToBytes(args.recipientScript);
  if (!bytesEqual(recipient.script, wantRecipient)) {
    throw new Error("recipient script does not match reviewed destination");
  }
  if (recipient.amount !== BigInt(args.recipientAmount)) {
    throw new Error("recipient amount does not match reviewed amount");
  }

  let outSum = 0n;
  for (let i = 0; i < tx.outputsLength; i++) outSum += tx.getOutput(i).amount;
  const fee = input.witnessUtxo.amount - outSum;
  if (fee < 0n) throw new Error("negative fee");
  if (fee !== BigInt(args.fee)) throw new Error("fee does not match reviewed fee");

  const [control, leaf] = input.tapLeafScript[0];
  return {
    source: args.expectEmptyWitness ? "draft-psbt" : "bound-psbt",
    prevout: `${bytesToHex(sha256d(prev.toBytes(true, false)).reverse())}:${args.vout}`,
    inputValue: input.witnessUtxo.amount.toString(),
    recipientScript: bytesToHex(recipient.script),
    recipientAmount: recipient.amount.toString(),
    changeScript: change ? bytesToHex(change.script) : "",
    changeAmount: change ? change.amount.toString() : "0",
    fee: fee.toString(),
    sighash: "SIGHASH_DEFAULT",
    leafScript: bytesToHex(leaf),
    controlBlock: normalize(control),
    packet,
    packetIndex,
  };
}

function assertDraftBoundEqual(draft, bound, packetIndex) {
  if (draft.version !== bound.version) throw new Error("bind mutated version");
  if (draft.lockTime !== bound.lockTime) throw new Error("bind mutated locktime");
  if (JSON.stringify(draft.inputs) !== JSON.stringify(bound.inputs)) {
    throw new Error("bind mutated input fields");
  }
  if (draft.outputs.length !== bound.outputs.length) {
    throw new Error("bind mutated output count");
  }
  if (packetIndex < 0 || packetIndex >= bound.outputs.length) {
    throw new Error("packet output index");
  }
  for (let i = 0; i < draft.outputs.length; i++) {
    const before = draft.outputs[i];
    const after = bound.outputs[i];
    if (before.amount !== after.amount) throw new Error("bind mutated output amount");
    const beforeRest = { ...before, script: undefined };
    const afterRest = { ...after, script: undefined };
    if (JSON.stringify(beforeRest) !== JSON.stringify(afterRest)) {
      throw new Error("bind mutated output fields");
    }
    if (i === packetIndex) {
      if (before.script === after.script) {
        throw new Error("bind did not insert direct-auth witness");
      }
      continue;
    }
    if (before.script !== after.script) throw new Error("bind mutated non-packet output");
  }
}

function expectedDirectWitness(directSig) {
  if (!directSig) throw new Error("directSig required");
  const sig = hexToBytes(directSig);
  if (sig.length !== 64) throw new Error("direct signature must be 64 bytes");
  return [sig];
}

function operationalScript(args) {
  if (args.operationalScriptHex) return hexToBytes(args.operationalScriptHex);
  if (args.operationalAddress) return scriptFromAddress(args.operationalAddress);
  throw new Error("operational script required");
}

function parseCanonicalPacket(script, expectEmptyWitness) {
  const packets = parseExtensionPackets(script);
  if (packets.length !== 1 || packets[0].type !== PACKET_TYPE) {
    throw new Error("extension must contain exactly one type 0x01 packet");
  }
  const entry = parseEmulatorPacket(packets[0].data);
  if (entry.vin !== 0) throw new Error("emulator entry vin");
  if (entry.script.length === 0) throw new Error("empty authorization script");
  if (expectEmptyWitness && entry.witness.length !== 0) {
    throw new Error("draft packet witness must be empty");
  }
  if (!expectEmptyWitness && entry.witness.length !== 1) {
    throw new Error("bound packet must carry the one-item direct signature");
  }
  return {
    vin: entry.vin,
    script: bytesToHex(entry.script),
    witness: entry.witness.map(bytesToHex),
  };
}

export function parseExtensionPackets(script) {
  const payload = pushedPayload(script);
  if (!payload || payload.length < ARK_MAGIC.length || !bytesEqual(payload.slice(0, 3), ARK_MAGIC)) {
    throw new Error("not an ark extension");
  }
  let off = 3;
  const packets = [];
  while (off < payload.length) {
    const type = payload[off++];
    const [len, n] = readUvarint(payload, off);
    off = n;
    const size = Number(len);
    if (off + size > payload.length) throw new Error("truncated extension packet");
    packets.push({ type, data: payload.slice(off, off + size) });
    off += size;
  }
  if (packets.length === 0) throw new Error("missing packets");
  const seen = new Set();
  for (const p of packets) {
    if (seen.has(p.type)) throw new Error("duplicate packet type");
    seen.add(p.type);
  }
  return packets;
}

export function parseEmulatorPacket(data) {
  let off = 0;
  const [count, n] = readCompactSize(data, off);
  off = n;
  if (count !== 1n) throw new Error("exactly one emulator entry required");
  if (off + 2 > data.length) throw new Error("truncated emulator vin");
  const vin = data[off] | (data[off + 1] << 8);
  off += 2;
  const [scriptLen, n2] = readCompactSize(data, off);
  off = n2;
  const sl = Number(scriptLen);
  if (off + sl > data.length) throw new Error("truncated emulator script");
  const script = data.slice(off, off + sl);
  off += sl;
  const [witLen, n3] = readCompactSize(data, off);
  off = n3;
  const wl = Number(witLen);
  if (off + wl > data.length) throw new Error("truncated emulator witness");
  const witBytes = data.slice(off, off + wl);
  off += wl;
  if (off !== data.length) throw new Error("unexpected emulator packet trailer");
  return { vin, script, witness: wl === 0 ? [] : readTxWitness(witBytes) };
}

export function encodeExtensionScript(packets) {
  const payload = [ARK_MAGIC];
  for (const p of packets) {
    payload.push(Uint8Array.of(p.type));
    payload.push(writeUvarint(p.data.length));
    payload.push(p.data);
  }
  const body = concat(payload);
  return concat([Uint8Array.of(0x6a), pushBytes(body)]);
}

export function encodeEmulatorPacket(entry) {
  const script = toBytes(entry.script);
  const witness = (entry.witness || []).map(toBytes);
  const wit = witness.length ? writeTxWitness(witness) : new Uint8Array(0);
  return concat([
    writeCompactSize(1),
    Uint8Array.of(entry.vin & 0xff, (entry.vin >> 8) & 0xff),
    writeCompactSize(script.length),
    script,
    writeCompactSize(wit.length),
    wit,
  ]);
}

function isExtensionScript(script) {
  try {
    const payload = pushedPayload(script);
    return !!(payload && payload.length >= 3 && bytesEqual(payload.slice(0, 3), ARK_MAGIC));
  } catch {
    return false;
  }
}

function pushedPayload(script) {
  if (!script || script[0] !== 0x6a) return null;
  const [data, end] = readPush(script, 1);
  if (end !== script.length) return null;
  return data;
}

function readPush(buf, off) {
  if (off >= buf.length) throw new Error("truncated push");
  const op = buf[off];
  if (op > 0 && op < 76) {
    const end = off + 1 + op;
    if (end > buf.length) throw new Error("truncated push data");
    return [buf.slice(off + 1, end), end];
  }
  if (op === 0x4c) {
    if (off + 2 > buf.length) throw new Error("truncated pushdata1");
    const n = buf[off + 1];
    const end = off + 2 + n;
    if (end > buf.length) throw new Error("truncated push data");
    return [buf.slice(off + 2, end), end];
  }
  if (op === 0x4d) {
    if (off + 3 > buf.length) throw new Error("truncated pushdata2");
    const n = buf[off + 1] | (buf[off + 2] << 8);
    const end = off + 3 + n;
    if (end > buf.length) throw new Error("truncated push data");
    return [buf.slice(off + 3, end), end];
  }
  throw new Error("unsupported push opcode");
}

function pushBytes(data) {
  if (data.length < 76) return concat([Uint8Array.of(data.length), data]);
  if (data.length <= 0xff) return concat([Uint8Array.of(0x4c, data.length), data]);
  if (data.length <= 0xffff) {
    return concat([Uint8Array.of(0x4d, data.length & 0xff, (data.length >> 8) & 0xff), data]);
  }
  throw new Error("push too large");
}

function readTxWitness(buf) {
  let off = 0;
  const [count, n] = readCompactSize(buf, off);
  off = n;
  const items = [];
  for (let i = 0; i < Number(count); i++) {
    const [len, n2] = readCompactSize(buf, off);
    off = n2;
    const size = Number(len);
    if (off + size > buf.length) throw new Error("truncated witness item");
    items.push(buf.slice(off, off + size));
    off += size;
  }
  if (off !== buf.length) throw new Error("unexpected witness trailer");
  return items;
}

function writeTxWitness(items) {
  const parts = [writeCompactSize(items.length)];
  for (const item of items) {
    parts.push(writeCompactSize(item.length));
    parts.push(item);
  }
  return concat(parts);
}

function readCompactSize(buf, off) {
  if (off >= buf.length) throw new Error("truncated compact size");
  const first = buf[off];
  if (first < 0xfd) return [BigInt(first), off + 1];
  if (first === 0xfd) {
    if (off + 3 > buf.length) throw new Error("truncated compact size");
    return [BigInt(buf[off + 1] | (buf[off + 2] << 8)), off + 3];
  }
  if (first === 0xfe) {
    if (off + 5 > buf.length) throw new Error("truncated compact size");
    return [BigInt(buf[off + 1] | (buf[off + 2] << 8) | (buf[off + 3] << 16) | (buf[off + 4] << 24)), off + 5];
  }
  throw new Error("oversized compact size");
}

function writeCompactSize(n) {
  if (n < 0xfd) return Uint8Array.of(n);
  if (n <= 0xffff) return Uint8Array.of(0xfd, n & 0xff, (n >> 8) & 0xff);
  if (n <= 0xffffffff) {
    return Uint8Array.of(0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff);
  }
  throw new Error("compact size too large");
}

function readUvarint(buf, off) {
  let x = 0n;
  let s = 0n;
  for (let i = 0; i < 10; i++) {
    if (off + i >= buf.length) throw new Error("truncated uvarint");
    const b = BigInt(buf[off + i]);
    if (b < 0x80n) return [x | (b << s), off + i + 1];
    x |= (b & 0x7fn) << s;
    s += 7n;
  }
  throw new Error("uvarint overflow");
}

function writeUvarint(n) {
  const out = [];
  let x = BigInt(n);
  while (x >= 0x80n) {
    out.push(Number((x & 0x7fn) | 0x80n));
    x >>= 7n;
  }
  out.push(Number(x));
  return Uint8Array.from(out);
}

function normalize(value) {
  if (value == null) return value;
  if (value instanceof Uint8Array) return bytesToHex(value);
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) return value.map(normalize);
  if (typeof value === "object") {
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = normalize(value[key]);
    return out;
  }
  return value;
}

function stripSigs(snap) {
  return {
    ...snap,
    inputs: snap.inputs.map((input) => {
      const copy = { ...input };
      delete copy.tapScriptSig;
      delete copy.partialSig;
      delete copy.tapKeySig;
      return copy;
    }),
  };
}

function sha256d(bytes) {
  return sha256(sha256(toBytes(bytes)));
}

function requireHex(h, name) {
  const v = String(h || "").toLowerCase();
  if (!/^[0-9a-f]+$/.test(v) || v.length % 2 !== 0) throw new Error(name);
  return v;
}

function toBytes(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (Array.isArray(value)) return Uint8Array.from(value);
  throw new Error("bytes");
}

function concat(parts) {
  const size = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(size);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}
