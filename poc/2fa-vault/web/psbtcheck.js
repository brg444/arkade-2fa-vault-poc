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
export const MAX_MONEY_SATS = 21_000_000n * 100_000_000n;
export const MAX_PSBT_BYTES = 256 * 1024;
export const MAX_PREV_TX_BYTES = 1024 * 1024;
export const PACKET_TYPE = 0x01;
export const ARK_MAGIC = new Uint8Array([0x41, 0x52, 0x4b]);
const REGTEST = Object.freeze({ ...TEST_NETWORK, bech32: "bcrt" });

export function bytesToHex(b) {
  return [...toBytes(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(h, maxBytes = MAX_PREV_TX_BYTES) {
  if (typeof h !== "string" || h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) {
    throw new Error("hex");
  }
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0 || h.length > maxBytes * 2) {
    throw new Error("hex input too large");
  }
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function b64ToBytes(b64, maxBytes = MAX_PSBT_BYTES) {
  if (typeof b64 !== "string" || b64.length === 0 || b64.length % 4 !== 0 ||
      !/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) {
    throw new Error("base64");
  }
  const padding = b64.endsWith("==") ? 2 : (b64.endsWith("=") ? 1 : 0);
  const decodedLength = (b64.length / 4) * 3 - padding;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0 || decodedLength > maxBytes) {
    throw new Error("base64 input too large");
  }
  const bin = atob(b64);
  if (bin.length !== decodedLength) throw new Error("base64");
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

export function parseExactSats(value, name, minimum = 0n) {
  const raw = String(value ?? "").trim();
  if (!/^(0|[1-9][0-9]*)$/.test(raw)) throw new Error(`${name} must be an exact non-negative integer`);
  const amount = BigInt(raw);
  if (amount < minimum) throw new Error(`${name} is below the minimum`);
  if (amount > MAX_MONEY_SATS) throw new Error(`${name} exceeds MAX_MONEY`);
  const number = Number(amount);
  if (!Number.isSafeInteger(number) || BigInt(number) !== amount) {
    throw new Error(`${name} is not exactly representable`);
  }
  return { text: raw, bigint: amount, number };
}

export function parseExactVout(value) {
  const raw = String(value ?? "").trim();
  if (!/^(0|[1-9][0-9]*)$/.test(raw)) throw new Error("vout must be an exact non-negative integer");
  const vout = BigInt(raw);
  if (vout > 0xffffffffn) throw new Error("vout exceeds uint32");
  return { text: raw, number: Number(vout) };
}

export function scriptFromAddress(addr, network) {
  if (!addr) throw new Error("operational address required");
  return OutScript.encode(Address(addressNetwork(network)).decode(addr));
}

function addressNetwork(network) {
  if (network === "regtest") return REGTEST;
  if (network === "mutinynet") return TEST_NETWORK;
  throw new Error("unsupported vault network");
}

export function snapshotPSBT(tx) {
  if (!(tx instanceof Transaction)) throw new Error("psbt snapshot requires parsed transaction");
  const inputs = [];
  for (let i = 0; i < tx.inputsLength; i++) inputs.push(normalize(tx.getInput(i)));
  const outputs = [];
  for (let i = 0; i < tx.outputsLength; i++) outputs.push(normalize(tx.getOutput(i)));
  return {
    global: normalize(tx.global),
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

export function assertPhoneRoutineBIP340Pub(derivedHex, persistedHex, statusHex) {
  const derived = requireHex(derivedHex, "derived PhoneRoutineBIP340 pub");
  if (persistedHex && requireHex(persistedHex, "persisted PhoneRoutineBIP340 pub") !== derived) {
    throw new Error("derived PhoneRoutineBIP340 pub does not match the persisted pub");
  }
  if (statusHex && requireHex(statusHex, "status PhoneRoutineBIP340 pub") !== derived) {
    throw new Error("derived PhoneRoutineBIP340 pub does not match vault status");
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
    arkadeChallenge: parsed.arkadeChallenge,
    leafScript: parsed.leafScript,
    controlBlock: parsed.controlBlock,
    packetVin: parsed.packet.vin,
    packetWitnessItems: parsed.packet.witness.length,
  };
}

export function assertArkadeChallenge(local, server) {
  const expected = String(local || "").toLowerCase();
  const received = String(server || "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(expected) || !/^[0-9a-f]{64}$/.test(received) || expected !== received) {
    throw new Error("authorizer preflight challenge does not match the locally computed Arkade sighash");
  }
  return expected;
}

export function validateAuthorizedPSBT(args) {
  if (!args || !args.submittedB64 || !args.authorizedB64) {
    throw new Error("submitted and authorized psbts required");
  }
  const submitted = parsePSBT(args.submittedB64);
  const authorized = parsePSBT(args.authorizedB64);
  if (submitted.inputsLength !== 1 || authorized.inputsLength !== 1) throw new Error("authorized psbt must have exactly one input");
  const mismatch = firstMismatch(
    withoutTapScriptSigs(snapshotPSBT(submitted)),
    withoutTapScriptSigs(snapshotPSBT(authorized)),
  );
  if (mismatch) {
    throw new Error(`authorize mutated non-signature psbt fields at ${mismatch}`);
  }
  const before = tapSigs(submitted.getInput(0));
  const after = tapSigs(authorized.getInput(0));
  if (before.length !== 1) throw new Error("submitted psbt must carry only the PhoneRoutineBIP340 signature");
  if (after.length !== 3) {
    throw new Error("authorized psbt must contain PhoneRoutineBIP340, VaultCosigner, and ArkadeCosigner signatures only");
  }
  const phoneRoutine = before[0];
  const phoneRoutineCompressed = requireHex(args.phoneRoutineBip340PubHex, "PhoneRoutineBIP340 pub");
  if (!/^(02|03)[0-9a-f]{64}$/.test(phoneRoutineCompressed)) throw new Error("PhoneRoutineBIP340 pub must be compressed secp256k1");
  if (phoneRoutine.pub !== phoneRoutineCompressed.slice(2)) throw new Error("submitted PhoneRoutineBIP340 signature key");
  if (phoneRoutine.sig.length !== 128) throw new Error("PhoneRoutineBIP340 signature must be 64 bytes");
  const authInput = submitted.getInput(0);
  if (!authInput.witnessUtxo || !authInput.tapLeafScript || authInput.tapLeafScript.length !== 1) throw new Error("authorized tap leaf required");
  const leafBytes = toBytes(authInput.tapLeafScript[0][1]);
  if (leafBytes.length < 2) throw new Error("tap leaf");
  const script = leafBytes.subarray(0, -1);
  const ver = leafBytes[leafBytes.length - 1];
  const leafHash = bytesToHex(schnorr.utils.taggedHash("TapLeaf", Uint8Array.of(ver), writeCompactSize(script.length), script));
  if (phoneRoutine.leaf !== leafHash) throw new Error("PhoneRoutineBIP340 signature leaf");
  const msg = submitted.preimageWitnessV1(0, [authInput.witnessUtxo.script], authInput.sighashType ?? SigHash.DEFAULT, [authInput.witnessUtxo.amount], -1, script, ver);
  if (!schnorr.verify(hexToBytes(phoneRoutine.sig), msg, hexToBytes(phoneRoutine.pub))) throw new Error("PhoneRoutineBIP340 signature invalid");
  if (after.filter((s) => sameTapSig(s, phoneRoutine)).length !== 1) throw new Error("authorized response mutated the PhoneRoutineBIP340 signature");
  const extras = after.filter((s) => !sameTapSig(s, phoneRoutine));
  if (extras.length !== 2) throw new Error("authorized routine signature delta");
  const wantVaultCosigner = requireHex(args.tweakedVaultCosignerXOnly, "tweaked VaultCosigner x-only");
  if (!/^[0-9a-f]{64}$/.test(wantVaultCosigner)) throw new Error("tweaked VaultCosigner x-only must be 32 bytes");
  const wantArkade = requireHex(args.tweakedArkadeCosignerXOnly, "tweaked ArkadeCosigner x-only");
  if (!/^[0-9a-f]{64}$/.test(wantArkade)) throw new Error("tweaked ArkadeCosigner x-only must be 32 bytes");
  if (new Set([phoneRoutine.pub, wantVaultCosigner, wantArkade]).size !== 3) {
    throw new Error("routine signer keys must be independent");
  }
  const expected = new Map([
    [wantVaultCosigner, "VaultCosigner"],
    [wantArkade, "ArkadeCosigner"],
  ]);
  for (const extra of extras) {
    const role = expected.get(extra.pub);
    if (!role) {
      throw new Error("authorized response contains a duplicate or substituted routine cosigner");
    }
    if (extra.leaf !== leafHash) throw new Error(`${role} signature leaf`);
    if (extra.sig.length !== 128) throw new Error(`${role} signature must be 64 bytes`);
    if (!schnorr.verify(hexToBytes(extra.sig), msg, hexToBytes(extra.pub))) {
      throw new Error(`${role} signature invalid`);
    }
    expected.delete(extra.pub);
  }
  if (expected.size !== 0) throw new Error("authorized response is missing a required routine cosigner signature");
  // The txid excludes witness data, so the PSBT's exact unsigned transaction
  // independently commits to the txid that finalization and publication must
  // preserve. Signatures are verified above before this value is released.
  const transactionId = bytesToHex(Uint8Array.from(sha256d(authorized.toBytes(true, false))).reverse());
  return { vaultCosignerPub: wantVaultCosigner, arkadeCosignerPub: wantArkade, transactionId };
}

function tapSigs(input) {
  return (input.tapScriptSig || []).map(normalizeTapSig);
}

function normalizeTapSig(entry) {
  const meta = entry[0];
  const sig = toBytes(entry[1]);
  return {
    pub: bytesToHex(toBytes(meta.pubKey)),
    leaf: bytesToHex(toBytes(meta.leafHash)),
    sig: bytesToHex(sig),
  };
}

function sameTapSig(a, b) { return a.pub === b.pub && a.leaf === b.leaf && a.sig === b.sig; }

export function phoneRoutineSignPSBT(b64, priv) {
  const tx = parsePSBT(b64);
  if (tx.inputsLength !== 1) throw new Error("local sign requires exactly one input");
  const before = snapshotPSBT(tx);
  // @scure/btc-signer's updateInput merge drops unknown PSBT keys. The
  // Arkade PrevoutTxField is intentionally unknown to the browser library,
  // so restore the exact cloned map after signing and then verify the full
  // PSBT delta below.
  const preservedUnknown = tx.getInput(0).unknown;
  tx.sign(toBytes(priv));
  if (preservedUnknown) tx.inputs[0].unknown = preservedUnknown;
  else delete tx.inputs[0].unknown;
  const signed = tx.toPSBT();
  const after = snapshotPSBT(Transaction.fromPSBT(signed, PSBT_OPTS));
  const mismatch = firstMismatch(withoutTapScriptSigs(before), withoutTapScriptSigs(after));
  if (mismatch) {
    throw new Error(`local sign mutated non-signature psbt field: ${mismatch}`);
  }
  return bytesToB64(signed);
}

function inspectPSBT(args) {
  const tx = args.tx || parsePSBT(args.b64);
  if (tx.version !== 2) throw new Error("transaction version must be 2");
  if (tx.lockTime !== 0) throw new Error("locktime must be zero");
  if (tx.inputsLength !== 1) throw new Error("exactly one input required");
  if (tx.outputsLength !== 3) throw new Error("routine spend requires recipient, recursive change, and packet outputs");
  const input = tx.getInput(0);
  if (input.sequence !== 0xffffffff) {
    throw new Error("routine sequence must be final");
  }
  if ((input.sighashType ?? SigHash.DEFAULT) !== SigHash.DEFAULT) {
    throw new Error("sighash must be SIGHASH_DEFAULT");
  }
  if (!input.witnessUtxo) throw new Error("witness utxo required");
  assertMoneyRange(input.witnessUtxo.amount, "witness utxo amount");
  if (!input.tapLeafScript || input.tapLeafScript.length !== 1) {
    throw new Error("exactly one routine tap leaf required");
  }
  const reviewedVout = parseExactVout(args.vout);
  const reviewedAmount = parseExactSats(args.recipientAmount, "recipient amount", DUST_SATS);
  const reviewedFee = parseExactSats(args.fee, "fee");
  if (reviewedAmount.bigint + reviewedFee.bigint > MAX_MONEY_SATS) {
    throw new Error("recipient amount plus fee exceeds MAX_MONEY");
  }
  const prevRaw = hexToBytes(args.prevTxHex, MAX_PREV_TX_BYTES);
  const prev = Transaction.fromRaw(prevRaw, PSBT_OPTS);
  if (input.index !== reviewedVout.number) throw new Error("prevout vout mismatch");
  const prevTxID = Uint8Array.from(sha256d(prev.toBytes(true, false))).reverse();
  if (!bytesEqual(input.txid, prevTxID)) {
    throw new Error("prevout txid mismatch");
  }
  const prevOut = prev.getOutput(reviewedVout.number);
  if (!prevOut) throw new Error("prevout vout out of range");
  assertMoneyRange(prevOut.amount, "prevout amount");
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
    assertMoneyRange(out.amount, `output ${i} amount`);
    const script = toBytes(out.script);
    if (isExtensionScript(script)) {
      if (packet) throw new Error("multiple extension outputs");
      if (out.amount !== 0n) throw new Error("extension output must be zero value");
      packet = parseCanonicalPacket(script, args.expectEmptyWitness);
      packetIndex = i;
      if (i !== 2) throw new Error("packet output must be last");
      continue;
    }
    if (bytesEqual(script, operational)) {
      if (change) throw new Error("multiple change outputs");
      if (out.amount < DUST_SATS) throw new Error("change below dust");
      if (i !== 1) throw new Error("recursive change must be output one");
      change = { script, amount: out.amount };
      continue;
    }
    if (recipient) throw new Error("multiple recipient outputs");
    if (script.length === 0 || script[0] === 0x6a) throw new Error("unexpected op_return or unspendable output");
    if (!isNativeWitnessProgram(script)) throw new Error("routine recipient must be a native segwit output");
    if (out.amount < DUST_SATS) throw new Error("recipient below dust");
    if (i !== 0) throw new Error("recipient must be output zero");
    recipient = { script, amount: out.amount };
  }
  if (!recipient) throw new Error("missing recipient");
  if (!packet) throw new Error("missing emulator packet output");
  if (!change) throw new Error("routine spend requires non-dust recursive change");

  const wantRecipient = hexToBytes(args.recipientScript);
  if (!bytesEqual(recipient.script, wantRecipient)) {
    throw new Error("recipient script does not match reviewed destination");
  }
  if (recipient.amount !== reviewedAmount.bigint) {
    throw new Error("recipient amount does not match reviewed amount");
  }

  let outSum = 0n;
  for (let i = 0; i < tx.outputsLength; i++) {
    outSum += tx.getOutput(i).amount;
    if (outSum > MAX_MONEY_SATS) throw new Error("total output amount exceeds MAX_MONEY");
  }
  const fee = input.witnessUtxo.amount - outSum;
  if (fee < 0n) throw new Error("negative fee");
  if (fee !== reviewedFee.bigint) throw new Error("fee does not match reviewed fee");

  const [control, leaf] = input.tapLeafScript[0];
  const challenge = computeArkadeChallenge(tx);
  return {
    source: args.expectEmptyWitness ? "draft-psbt" : "bound-psbt",
    prevout: `${bytesToHex(prevTxID)}:${reviewedVout.text}`,
    inputValue: input.witnessUtxo.amount.toString(),
    recipientScript: bytesToHex(recipient.script),
    recipientAmount: recipient.amount.toString(),
    changeScript: change ? bytesToHex(change.script) : "",
    changeAmount: change ? change.amount.toString() : "0",
    fee: fee.toString(),
    sighash: "SIGHASH_DEFAULT",
    arkadeChallenge: bytesToHex(challenge),
    leafScript: bytesToHex(leaf),
    controlBlock: normalize(control),
    packet,
    packetIndex,
  };
}

function assertMoneyRange(amount, name) {
  if (typeof amount !== "bigint" || amount < 0n || amount > MAX_MONEY_SATS) {
    throw new Error(`${name} is outside the Bitcoin money range`);
  }
}

function isNativeWitnessProgram(script) {
  if (!(script instanceof Uint8Array) || script.length < 4 || script.length > 42) return false;
  const version = script[0];
  if (version !== 0x00 && (version < 0x51 || version > 0x60)) return false;
  const programLength = script[1];
  return programLength >= 2 && programLength <= 40 && script.length === programLength + 2;
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
  const fromHex = args.operationalScriptHex ? hexToBytes(args.operationalScriptHex) : null;
  const fromAddress = args.operationalAddress
    ? scriptFromAddress(args.operationalAddress, args.network)
    : null;
  if (fromHex && fromAddress && !bytesEqual(fromHex, fromAddress)) {
    throw new Error("operational address does not match persisted script");
  }
  if (fromHex) return fromHex;
  if (fromAddress) return fromAddress;
  throw new Error("operational script required");
}

function parseCanonicalPacket(script, expectEmptyWitness) {
  const packets = parseExtensionPackets(script);
  if (!bytesEqual(encodeExtensionScript(packets), script)) {
    throw new Error("non-canonical ark extension encoding");
  }
  if (packets.length !== 1 || packets[0].type !== PACKET_TYPE) {
    throw new Error("extension must contain exactly one type 0x01 packet");
  }
  const entry = parseEmulatorPacket(packets[0].data);
  if (!bytesEqual(encodeEmulatorPacket(entry), packets[0].data)) {
    throw new Error("non-canonical emulator packet encoding");
  }
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

// computeArkadeChallenge independently implements the restricted digest used
// by this one-input SIGHASH_DEFAULT vault template. It mirrors
// pkg/arkade.CalcArkadeScriptSignatureHash: BIP342's SigMsg layout, Arkade's
// witness-masked extension output, and the distinct ArkadeTapSighash tag.
export function computeArkadeChallenge(tx) {
  if (!(tx instanceof Transaction)) throw new Error("arkade challenge requires parsed transaction");
  if (tx.inputsLength !== 1) throw new Error("arkade challenge requires exactly one input");
  const input = tx.getInput(0);
  if (!input.witnessUtxo) throw new Error("arkade challenge witness utxo");
  if (!input.tapLeafScript || input.tapLeafScript.length !== 1) {
    throw new Error("arkade challenge tap leaf");
  }
  if ((input.sighashType ?? SigHash.DEFAULT) !== SigHash.DEFAULT) {
    throw new Error("arkade challenge requires SIGHASH_DEFAULT");
  }
  const txid = toBytes(input.txid);
  if (txid.length !== 32) throw new Error("arkade challenge input txid");
  const leafBytes = toBytes(input.tapLeafScript[0][1]);
  if (leafBytes.length < 2) throw new Error("arkade challenge tap leaf");
  const leafScript = leafBytes.subarray(0, -1);
  const leafVersion = leafBytes[leafBytes.length - 1];
  const outputs = [];
  for (let i = 0; i < tx.outputsLength; i++) {
    const out = tx.getOutput(i);
    outputs.push(serializeOutput(out.amount, maskEmulatorWitness(toBytes(out.script))));
  }
  const sigMsg = concat([
    Uint8Array.of(0x00, SigHash.DEFAULT),
    i32LE(tx.version),
    u32LE(tx.lockTime),
    sha256(concat([reverseBytes(txid), u32LE(input.index)])),
    sha256(u64LE(input.witnessUtxo.amount)),
    sha256(varBytes(toBytes(input.witnessUtxo.script))),
    sha256(u32LE(input.sequence ?? 0xffffffff)),
    sha256(concat(outputs)),
    Uint8Array.of(0x02),
    u32LE(0),
    schnorr.utils.taggedHash(
      "TapLeaf",
      Uint8Array.of(leafVersion),
      writeCompactSize(leafScript.length),
      leafScript,
    ),
    Uint8Array.of(0x00),
    u32LE(0xffffffff),
  ]);
  return schnorr.utils.taggedHash("ArkadeTapSighash", sigMsg);
}

function maskEmulatorWitness(script) {
  if (!isExtensionScript(script)) return script;
  const packets = parseExtensionPackets(script);
  if (!bytesEqual(encodeExtensionScript(packets), script)) {
    throw new Error("non-canonical ark extension encoding");
  }
  let found = false;
  const masked = packets.map((packet) => {
    if (packet.type !== PACKET_TYPE) return packet;
    if (found) throw new Error("multiple emulator packets");
    found = true;
    const entry = parseEmulatorPacket(packet.data);
    return {
      type: packet.type,
      data: encodeEmulatorPacket({ vin: entry.vin, script: entry.script, witness: [] }),
    };
  });
  return found ? encodeExtensionScript(masked) : script;
}

function serializeOutput(amount, script) {
  return concat([u64LE(amount), varBytes(script)]);
}

function varBytes(bytes) {
  const value = toBytes(bytes);
  return concat([writeCompactSize(value.length), value]);
}

function reverseBytes(bytes) {
  return Uint8Array.from(toBytes(bytes)).reverse();
}

function i32LE(value) {
  if (!Number.isInteger(value) || value < -0x80000000 || value > 0x7fffffff) throw new Error("int32");
  return u32LE(value >>> 0);
}

function u32LE(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) throw new Error("uint32");
  return Uint8Array.of(value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff);
}

function u64LE(value) {
  let n = BigInt(value);
  if (n < 0n || n > 0xffffffffffffffffn) throw new Error("uint64");
  const out = new Uint8Array(8);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
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
    const size = boundedNumber(len, payload.length - off, "extension packet length");
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
  const sl = boundedNumber(scriptLen, data.length - off, "emulator script length");
  if (off + sl > data.length) throw new Error("truncated emulator script");
  const script = data.slice(off, off + sl);
  off += sl;
  const [witLen, n3] = readCompactSize(data, off);
  off = n3;
  const wl = boundedNumber(witLen, data.length - off, "emulator witness length");
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
  const itemCount = boundedNumber(count, buf.length, "witness item count");
  const items = [];
  for (let i = 0; i < itemCount; i++) {
    const [len, n2] = readCompactSize(buf, off);
    off = n2;
    const size = boundedNumber(len, buf.length - off, "witness item length");
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
    return [BigInt(buf[off + 1]) |
      (BigInt(buf[off + 2]) << 8n) |
      (BigInt(buf[off + 3]) << 16n) |
      (BigInt(buf[off + 4]) << 24n), off + 5];
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

function boundedNumber(value, max, name) {
  if (typeof value !== "bigint" || value < 0n || value > BigInt(max) || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`${name} exceeds remaining input`);
  }
  return Number(value);
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

function withoutTapScriptSigs(snap) {
  return {
    ...snap,
    inputs: snap.inputs.map((input, index) => {
      const copy = { ...input };
      if (index === 0) delete copy.tapScriptSig;
      return copy;
    }),
  };
}

function firstMismatch(a, b, path = "psbt") {
  if (a === b) return "";
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b)) return path;
    if (a.length !== b.length) return `${path}.length`;
    for (let i = 0; i < a.length; i++) {
      const mismatch = firstMismatch(a[i], b[i], `${path}[${i}]`);
      if (mismatch) return mismatch;
    }
    return "";
  }
  if (a && b && typeof a === "object" && typeof b === "object") {
    const aKeys = Object.keys(a).sort();
    const bKeys = Object.keys(b).sort();
    if (JSON.stringify(aKeys) !== JSON.stringify(bKeys)) {
      return `${path}.keys(${aKeys.join(",")} -> ${bKeys.join(",")})`;
    }
    for (const key of aKeys) {
      const mismatch = firstMismatch(a[key], b[key], `${path}.${key}`);
      if (mismatch) return mismatch;
    }
    return "";
  }
  return path;
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
