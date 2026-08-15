import { expect, test } from "bun:test";
import { schnorr, secp256k1, sha256 } from "./vendor/secp256k1.js";
import { SigHash, Transaction } from "./vendor/btc-signer.js";
import {
  PSBT_OPTS,
  assertDirectP256,
  assertHotPub,
  bytesToB64,
  bytesToHex,
  encodeEmulatorPacket,
  encodeExtensionScript,
  parsePSBT,
  snapshotPSBT,
  validateAuthorizedPSBT,
  validateBoundPSBT,
  validateDraftPSBT,
} from "./psbtcheck.js";

const vaultPriv = hex32(1);
const vaultScript = p2tr(vaultPriv);
const recipient = hexTo("0014aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
const evil = hexTo("0014bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
const authScript = hexTo("aabb");
const directSig = new Uint8Array(64).fill(0x11);

function hex32(n) {
  const out = new Uint8Array(32);
  out[31] = n;
  return out;
}

function hexTo(h) {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function p2tr(priv) {
  const xonly = secp256k1.getPublicKey(priv, true).slice(1);
  const script = new Uint8Array(34);
  script[0] = 0x51;
  script[1] = 0x20;
  script.set(xonly, 2);
  return script;
}

function leaf() {
  const xonly = secp256k1.getPublicKey(vaultPriv, true).slice(1);
  return [
    { version: 0xc0, internalKey: xonly, merklePath: [] },
    new Uint8Array([0x51, 0xc0]),
  ];
}

function fundedPrev(amount = 90000n) {
  const prev = new Transaction(PSBT_OPTS);
  prev.addInput({
    txid: new Uint8Array(32),
    index: 0,
    sequence: 0xffffffff,
    finalScriptSig: new Uint8Array(),
  });
  prev.addOutput({ script: vaultScript, amount });
  return prev;
}

function packetScript(witness = []) {
  return encodeExtensionScript([{
    type: 1,
    data: encodeEmulatorPacket({ vin: 0, script: authScript, witness }),
  }]);
}

function buildSpend({
  recipientScript = recipient,
  recipientAmount = 20000n,
  fee = 500n,
  witness = [],
  version = 2,
  lockTime = 0,
  sequence = 0xffffffff,
} = {}) {
  const prev = fundedPrev();
  const change = prev.getOutput(0).amount - recipientAmount - fee;
  const tx = new Transaction({ ...PSBT_OPTS, version, lockTime });
  tx.addInput({
    txid: sha256(sha256(prev.toBytes(true, false))),
    index: 0,
    sequence,
    witnessUtxo: { script: vaultScript, amount: prev.getOutput(0).amount },
    sighashType: SigHash.DEFAULT,
    tapLeafScript: [leaf()],
    unknown: [[{ type: 222, key: new TextEncoder().encode("prevouttx") }, prev.toBytes()]],
  });
  tx.addOutput({ script: recipientScript, amount: recipientAmount });
  if (change > 0n) tx.addOutput({ script: vaultScript, amount: change });
  tx.addOutput({ script: packetScript(witness), amount: 0n });
  return { prev, tx, b64: bytesToB64(tx.toPSBT()) };
}

function intent(built, overrides = {}) {
  return {
    prevTxHex: bytesToHex(built.prev.toBytes(true, false)),
    vout: 0,
    recipientScript: bytesToHex(recipient),
    recipientAmount: 20000,
    fee: 500,
    operationalScriptHex: bytesToHex(vaultScript),
    ...overrides,
  };
}

test("draft validation accepts the reviewed collaborative spend", () => {
  const built = buildSpend();
  const parsed = validateDraftPSBT({ draftB64: built.b64, ...intent(built) });
  expect(parsed.recipientAmount).toBe("20000");
  expect(parsed.fee).toBe("500");
  expect(parsed.sighash).toBe("SIGHASH_DEFAULT");
  expect(parsed.packet.witness.length).toBe(0);
});

test("bound validation allows only the direct-auth witness to change", () => {
  const draft = buildSpend();
  const bound = buildSpend({ witness: [directSig] });
  const parsed = validateBoundPSBT({
    draftB64: draft.b64,
    boundB64: bound.b64,
    directSig: bytesToHex(directSig),
    ...intent(draft),
  });
  expect(parsed.source).toBe("bound-psbt");
  expect(parsed.packet.witness.length).toBe(1);
});

test("bound validation rejects a substituted recipient", () => {
  const draft = buildSpend();
  const bound = buildSpend({
    recipientScript: evil,
    witness: [directSig],
  });
  expect(() => validateBoundPSBT({
    draftB64: draft.b64,
    boundB64: bound.b64,
    directSig: bytesToHex(directSig),
    ...intent(draft),
  })).toThrow(/recipient|mutated/);
});

test("inspect rejects non-canonical transaction version", () => {
  const draft = buildSpend();
  const bound = buildSpend({ version: 1, witness: [directSig] });
  expect(() => validateDraftPSBT({ draftB64: buildSpend({ version: 1 }).b64, ...intent(draft) }))
    .toThrow(/transaction version must be 2/);
  expect(() => validateBoundPSBT({
    draftB64: draft.b64,
    boundB64: bound.b64,
    directSig: bytesToHex(directSig),
    ...intent(draft),
  })).toThrow(/transaction version must be 2/);
});

test("inspect rejects non-zero locktime", () => {
  const draft = buildSpend();
  const bound = buildSpend({ lockTime: 1, witness: [directSig] });
  expect(() => validateDraftPSBT({ draftB64: buildSpend({ lockTime: 1 }).b64, ...intent(draft) }))
    .toThrow(/locktime must be zero/);
  expect(() => validateBoundPSBT({
    draftB64: draft.b64,
    boundB64: bound.b64,
    directSig: bytesToHex(directSig),
    ...intent(draft),
  })).toThrow(/locktime must be zero/);
});

test("inspect rejects non-final collaborative sequence", () => {
  const draft = buildSpend();
  const bound = buildSpend({ sequence: 0xfffffffe, witness: [directSig] });
  expect(() => validateDraftPSBT({ draftB64: buildSpend({ sequence: 0xfffffffe }).b64, ...intent(draft) }))
    .toThrow(/collaborative sequence must be final/);
  expect(() => validateBoundPSBT({
    draftB64: draft.b64,
    boundB64: bound.b64,
    directSig: bytesToHex(directSig),
    ...intent(draft),
  })).toThrow(/collaborative sequence must be final/);
});

test("hot pub mismatch is refused", () => {
  expect(() => assertHotPub("aa", "bb", "aa")).toThrow(/persisted/);
  expect(() => assertHotPub("aa", "aa", "cc")).toThrow(/status/);
});

test("direct P-256 must match derived, local record, and status", () => {
  expect(assertDirectP256("aa", "aa", "aa")).toBe("aa");
  expect(() => assertDirectP256("aa", "bb", "aa")).toThrow(/local record/);
  expect(() => assertDirectP256("aa", "aa", "cc")).toThrow(/status/);
  expect(() => assertDirectP256("aa", "aa", "")).toThrow(/status/);
});

test("PSBT snapshot preserves unknown prevout field", () => {
  const { tx, b64 } = buildSpend();
  const before = snapshotPSBT(tx);
  const after = snapshotPSBT(parsePSBT(b64));
  expect(after.inputs[0].unknown).toEqual(before.inputs[0].unknown);
});

function tapLeafParts(tx) {
  const leafBytes = tx.getInput(0).tapLeafScript[0][1];
  return { script: leafBytes.subarray(0, -1), ver: leafBytes[leafBytes.length - 1] };
}

function tapLeafHash(tx) {
  const { script, ver } = tapLeafParts(tx);
  return schnorr.utils.taggedHash("TapLeaf", Uint8Array.of(ver), Uint8Array.of(script.length), script);
}

function preimageWitnessV1Msg(tx) {
  const input = tx.getInput(0);
  const { script, ver } = tapLeafParts(tx);
  return tx.preimageWitnessV1(
    0,
    [input.witnessUtxo.script],
    input.sighashType ?? SigHash.DEFAULT,
    [input.witnessUtxo.amount],
    -1,
    script,
    ver,
  );
}

function authorizedPair() {
  const built = buildSpend();
  const tx = parsePSBT(built.b64);
  const hot = hex32(2);
  const prov = hex32(3);
  const hotPub = schnorr.getPublicKey(hot);
  const provPub = schnorr.getPublicKey(prov);
  const leafHash = tapLeafHash(tx);
  const msg = preimageWitnessV1Msg(tx);
  const hotSig = schnorr.sign(msg, hot);
  const provSig = schnorr.sign(msg, prov);
  tx.updateInput(0, {
    tapScriptSig: [[{ pubKey: hotPub, leafHash }, hotSig]],
  });
  const submitted = bytesToB64(tx.toPSBT());
  tx.updateInput(0, {
    tapScriptSig: [[{ pubKey: provPub, leafHash }, provSig]],
  }, true);
  const authorized = bytesToB64(tx.toPSBT());
  return {
    submitted,
    authorized,
    hotPriv: hot,
    provPriv: prov,
    hotPubHex: bytesToHex(secp256k1.getPublicKey(hot, true)),
    provPub: bytesToHex(provPub),
    leafHash,
    hotPub,
  };
}

function authorizeWith(submitted, providerPriv, leafHash = null, signature = null) {
  const tx = parsePSBT(submitted);
  const hash = leafHash || tapLeafHash(tx);
  const sig = signature || schnorr.sign(preimageWitnessV1Msg(tx), providerPriv);
  tx.updateInput(0, {
    tapScriptSig: [[{ pubKey: schnorr.getPublicKey(providerPriv), leafHash: hash }, sig]],
  }, true);
  return bytesToB64(tx.toPSBT());
}

function validatePair(pair, authorizedB64 = pair.authorized, overrides = {}) {
  return validateAuthorizedPSBT({
    submittedB64: pair.submitted,
    authorizedB64,
    hotPubHex: pair.hotPubHex,
    tweakedProviderXOnly: pair.provPub,
    ...overrides,
  });
}

test("authorized validation accepts exactly one extra valid provider signature", () => {
  const pair = authorizedPair();
  expect(validateAuthorizedPSBT({
    submittedB64: pair.submitted,
    authorizedB64: pair.authorized,
    hotPubHex: pair.hotPubHex,
    tweakedProviderXOnly: pair.provPub,
  }).providerPub).toBe(pair.provPub);
  expect(() => validateAuthorizedPSBT({
    submittedB64: pair.submitted,
    authorizedB64: pair.submitted,
    hotPubHex: pair.hotPubHex,
    tweakedProviderXOnly: pair.provPub,
  })).toThrow(/exactly one provider/);
});

test("authorized validation rejects a forged nonzero provider signature", () => {
  const pair = authorizedPair();
  const forgedTx = parsePSBT(pair.submitted);
  const forged = new Uint8Array(64).fill(1);
  forgedTx.updateInput(0, {
    tapScriptSig: [[{ pubKey: schnorr.getPublicKey(hex32(3)), leafHash: pair.leafHash }, forged]],
  }, true);
  expect(() => validateAuthorizedPSBT({
    submittedB64: pair.submitted,
    authorizedB64: bytesToB64(forgedTx.toPSBT()),
    hotPubHex: pair.hotPubHex,
    tweakedProviderXOnly: pair.provPub,
  })).toThrow(/provider signature invalid/);
});

test("authorized validation rejects a valid signature under an unpinned provider key", () => {
  const pair = authorizedPair();
  const attacker = hex32(9);
  expect(() => validatePair(pair, authorizeWith(pair.submitted, attacker)))
    .toThrow(/pinned vault key/);
});

test("authorized validation rejects 65-byte hot and provider signatures", () => {
  const pair = authorizedPair();
  const hot65 = parsePSBT(pair.submitted);
  const hotEntry = hot65.inputs[0].tapScriptSig[0];
  hot65.inputs[0].tapScriptSig = [[hotEntry[0], Uint8Array.from([...hotEntry[1], 1])]];
  const submitted65 = bytesToB64(hot65.toPSBT());
  expect(() => validateAuthorizedPSBT({
    submittedB64: submitted65,
    authorizedB64: authorizeWith(submitted65, pair.provPriv),
    hotPubHex: pair.hotPubHex,
    tweakedProviderXOnly: pair.provPub,
  })).toThrow(/hot signature must be 64 bytes/);

  const providerTx = parsePSBT(pair.submitted);
  const sig65 = Uint8Array.from([...schnorr.sign(preimageWitnessV1Msg(providerTx), pair.provPriv), 1]);
  expect(() => validatePair(pair, authorizeWith(pair.submitted, pair.provPriv, null, sig65)))
    .toThrow(/provider signature must be 64 bytes/);
});

test("authorized validation rejects a provider signature tagged with the wrong leaf", () => {
  const pair = authorizedPair();
  const wrongLeaf = new Uint8Array(32).fill(7);
  expect(() => validatePair(pair, authorizeWith(pair.submitted, pair.provPriv, wrongLeaf)))
    .toThrow(/provider signature leaf/);
});

test("authorized validation rejects mutation of the existing hot tuple", () => {
  const pair = authorizedPair();
  const tx = parsePSBT(pair.authorized);
  const [meta, sig] = tx.inputs[0].tapScriptSig[0];
  tx.inputs[0].tapScriptSig[0] = [meta, Uint8Array.from(sig.map((b, i) => i === 0 ? b ^ 1 : b))];
  expect(() => validatePair(pair, bytesToB64(tx.toPSBT())))
    .toThrow(/mutated the hot signature|provider signature delta/);
});

test("authorized validation rejects unrelated input signature metadata", () => {
  const pair = authorizedPair();
  const partial = parsePSBT(pair.authorized);
  partial.inputs[0].partialSig = [[secp256k1.getPublicKey(hex32(10), true), new Uint8Array([1])]];
  expect(() => validatePair(pair, bytesToB64(partial.toPSBT())))
    .toThrow(/non-signature psbt fields/);

  const keySig = parsePSBT(pair.authorized);
  keySig.inputs[0].tapKeySig = new Uint8Array(64).fill(4);
  expect(() => validatePair(pair, bytesToB64(keySig.toPSBT())))
    .toThrow(/non-signature psbt fields/);
});

test("authorized validation rejects changed global and output metadata", () => {
  const pair = authorizedPair();
  const global = parsePSBT(pair.authorized);
  global.global.unknown = [[{ type: 0xaa, key: new Uint8Array([1]) }, new Uint8Array([2])]];
  expect(() => validatePair(pair, bytesToB64(global.toPSBT())))
    .toThrow(/non-signature psbt fields/);

  const output = parsePSBT(pair.authorized);
  output.outputs[0].unknown = [[{ type: 0xaa, key: new Uint8Array([3]) }, new Uint8Array([4])]];
  expect(() => validatePair(pair, bytesToB64(output.toPSBT())))
    .toThrow(/non-signature psbt fields/);
});
