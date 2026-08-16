import { expect, test } from "bun:test";
import { schnorr, secp256k1, sha256 } from "./vendor/secp256k1.js";
import { Address, OutScript, SigHash, TEST_NETWORK, Transaction } from "./vendor/btc-signer.js";
import {
  PSBT_OPTS,
  MAX_MONEY_SATS,
  assertArkadeChallenge,
  assertDirectP256,
  assertPhoneRoutineBIP340Pub,
  b64ToBytes,
  bytesToB64,
  bytesToHex,
  encodeEmulatorPacket,
  encodeExtensionScript,
  phoneRoutineSignPSBT,
  hexToBytes,
  parseExactSats,
  parseExactVout,
  parsePSBT,
  scriptFromAddress,
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
const REGTEST = Object.freeze({ ...TEST_NETWORK, bech32: "bcrt" });

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
  prevAmount = 90000n,
  includeChange = true,
} = {}) {
  const prev = fundedPrev(prevAmount);
  const change = prev.getOutput(0).amount - recipientAmount - fee;
  const tx = new Transaction({ ...PSBT_OPTS, version, lockTime });
  tx.addInput({
    txid: Uint8Array.from(sha256(sha256(prev.toBytes(true, false)))).reverse(),
    index: 0,
    sequence,
    witnessUtxo: { script: vaultScript, amount: prev.getOutput(0).amount },
    sighashType: SigHash.DEFAULT,
    tapLeafScript: [leaf()],
    unknown: [[{ type: 222, key: new TextEncoder().encode("prevouttx") }, prev.toBytes()]],
  });
  tx.addOutput({ script: recipientScript, amount: recipientAmount });
  if (includeChange && change > 0n) tx.addOutput({ script: vaultScript, amount: change });
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

test("draft validation accepts the reviewed routine spend with recursive change", () => {
  const built = buildSpend();
  const parsed = validateDraftPSBT({ draftB64: built.b64, ...intent(built) });
  expect(parsed.recipientAmount).toBe("20000");
  expect(parsed.fee).toBe("500");
  expect(parsed.sighash).toBe("SIGHASH_DEFAULT");
  expect(parsed.packet.witness.length).toBe(0);
  // This fixed vector is independently checked by Go's
  // vault.Challenge in challenge_browser_parity_test.go.
  expect(parsed.arkadeChallenge).toBe("58a500edd00d9a7c371c280ab2c59b938ad9d15f9905f77831f1feee8fd10b94");
});

test("draft validation rejects a non-segwit routine recipient", () => {
  const legacy = hexTo("76a914aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa88ac");
  const built = buildSpend({ recipientScript: legacy });
  expect(() => validateDraftPSBT({
    draftB64: built.b64,
    ...intent(built, { recipientScript: bytesToHex(legacy) }),
  })).toThrow(/native segwit/);
});

test("routine validation rejects no-change full drain and replacement-descriptor change", () => {
  const fullDrain = buildSpend({ recipientAmount: 89500n, includeChange: false });
  expect(() => validateDraftPSBT({
    draftB64: fullDrain.b64,
    ...intent(fullDrain, { recipientAmount: 89500 }),
  })).toThrow(/recursive change/);

  const replacement = buildSpend();
  const changed = parsePSBT(replacement.b64);
  changed.outputs[1].script = p2tr(hex32(9));
  expect(() => validateDraftPSBT({
    draftB64: bytesToB64(changed.toPSBT()),
    ...intent(replacement),
  })).toThrow(/multiple recipient|recursive change/);
});

test("local Arkade challenge is witness-masked and preflight must match exactly", () => {
  const draft = buildSpend();
  const bound = buildSpend({ witness: [directSig] });
  const draftChallenge = validateDraftPSBT({ draftB64: draft.b64, ...intent(draft) }).arkadeChallenge;
  const boundChallenge = validateBoundPSBT({
    draftB64: draft.b64,
    boundB64: bound.b64,
    directSig: bytesToHex(directSig),
    ...intent(draft),
  }).arkadeChallenge;
  expect(boundChallenge).toBe(draftChallenge);
  expect(assertArkadeChallenge(draftChallenge, draftChallenge.toUpperCase())).toBe(draftChallenge);
  expect(() => assertArkadeChallenge(draftChallenge, "00".repeat(32))).toThrow(/locally computed Arkade/);
});

test("browser parsers reject fractional, negative, unsafe, and oversized values before allocation", () => {
  expect(parseExactSats("330", "amount", 330n).number).toBe(330);
  expect(parseExactSats(MAX_MONEY_SATS.toString(), "amount").bigint).toBe(MAX_MONEY_SATS);
  for (const value of ["", "-1", "1.5", "1e3", "+1", "01", (MAX_MONEY_SATS + 1n).toString()]) {
    expect(() => parseExactSats(value, "amount")).toThrow();
  }
  expect(parseExactVout("4294967295").number).toBe(0xffffffff);
  for (const value of ["", "-1", "1.5", "01", "4294967296"]) {
    expect(() => parseExactVout(value)).toThrow();
  }
  expect(() => b64ToBytes("AAAA", 2)).toThrow(/too large/);
  expect(() => b64ToBytes("%%%=")).toThrow(/base64/);
  expect(() => hexToBytes("00".repeat(5), 4)).toThrow(/too large/);
});

test("draft validation rejects out-of-range prevout, witness, and output money", () => {
  const excessiveInput = buildSpend({ prevAmount: MAX_MONEY_SATS + 1n });
  expect(() => validateDraftPSBT({ draftB64: excessiveInput.b64, ...intent(excessiveInput) }))
    .toThrow(/witness utxo amount.*money range/);

  const excessiveOutput = buildSpend();
  const changed = parsePSBT(excessiveOutput.b64);
  changed.outputs[0].amount = MAX_MONEY_SATS + 1n;
  expect(() => validateDraftPSBT({
    draftB64: bytesToB64(changed.toPSBT()),
    ...intent(excessiveOutput),
  })).toThrow(/output 0 amount.*money range/);
});

test("operational address decoding is explicitly network-bound", () => {
  const decoded = OutScript.decode(vaultScript);
  const regtestAddress = Address(REGTEST).encode(decoded);
  const mutinynetAddress = Address(TEST_NETWORK).encode(decoded);
  expect(bytesToHex(scriptFromAddress(regtestAddress, "regtest"))).toBe(bytesToHex(vaultScript));
  expect(bytesToHex(scriptFromAddress(mutinynetAddress, "mutinynet"))).toBe(bytesToHex(vaultScript));
  expect(() => scriptFromAddress(mutinynetAddress, "regtest")).toThrow();
  expect(() => scriptFromAddress(regtestAddress, "mutinynet")).toThrow();
});

test("draft validation treats an omitted Taproot sighash field as SIGHASH_DEFAULT", () => {
  const built = buildSpend();
  const tx = parsePSBT(built.b64);
  delete tx.inputs[0].sighashType;
  expect(validateDraftPSBT({
    draftB64: bytesToB64(tx.toPSBT()),
    ...intent(built),
  }).sighash).toBe("SIGHASH_DEFAULT");
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

test("inspect rejects non-final routine sequence", () => {
  const draft = buildSpend();
  const bound = buildSpend({ sequence: 0xfffffffe, witness: [directSig] });
  expect(() => validateDraftPSBT({ draftB64: buildSpend({ sequence: 0xfffffffe }).b64, ...intent(draft) }))
    .toThrow(/routine sequence must be final/);
  expect(() => validateBoundPSBT({
    draftB64: draft.b64,
    boundB64: bound.b64,
    directSig: bytesToHex(directSig),
    ...intent(draft),
  })).toThrow(/routine sequence must be final/);
});

test("phoneRoutineSecret pub mismatch is refused", () => {
  expect(() => assertPhoneRoutineBIP340Pub("aa", "bb", "aa")).toThrow(/persisted/);
  expect(() => assertPhoneRoutineBIP340Pub("aa", "aa", "cc")).toThrow(/status/);
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

test("phoneRoutineSecret signing restores the exact unknown PrevoutTxField dropped by scure updateInput", () => {
  const built = buildSpend();
  const tx = parsePSBT(built.b64);
  const phoneRoutineSecret = hex32(2);
  const hotXOnly = schnorr.getPublicKey(phoneRoutineSecret);
  const control = tx.inputs[0].tapLeafScript[0][0];
  const script = Uint8Array.from([0x20, ...hotXOnly, 0xac, 0xc0]);
  tx.inputs[0].tapLeafScript = [[control, script]];
  const unsigned = bytesToB64(tx.toPSBT());
  const before = snapshotPSBT(parsePSBT(unsigned));
  const signed = parsePSBT(phoneRoutineSignPSBT(unsigned, phoneRoutineSecret));
  const after = snapshotPSBT(signed);
  expect(after.inputs[0].unknown).toEqual(before.inputs[0].unknown);
  expect(signed.getInput(0).tapScriptSig.length).toBe(1);
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
  const phoneRoutineSecret = hex32(2);
  const prov = hex32(3);
  const arkade = hex32(4);
  const phoneRoutineBip340Pub = schnorr.getPublicKey(phoneRoutineSecret);
  const vaultCosignerPub = schnorr.getPublicKey(prov);
  const arkadePub = schnorr.getPublicKey(arkade);
  const leafHash = tapLeafHash(tx);
  const msg = preimageWitnessV1Msg(tx);
  const phoneRoutineSig = schnorr.sign(msg, phoneRoutineSecret);
  const provSig = schnorr.sign(msg, prov);
  const arkadeSig = schnorr.sign(msg, arkade);
  tx.updateInput(0, {
    tapScriptSig: [[{ pubKey: phoneRoutineBip340Pub, leafHash }, phoneRoutineSig]],
  });
  const submitted = bytesToB64(tx.toPSBT());
  tx.updateInput(0, {
    tapScriptSig: [[{ pubKey: vaultCosignerPub, leafHash }, provSig]],
  }, true);
  tx.updateInput(0, {
    tapScriptSig: [[{ pubKey: arkadePub, leafHash }, arkadeSig]],
  }, true);
  const authorized = bytesToB64(tx.toPSBT());
  return {
    submitted,
    authorized,
    phoneRoutinePriv: phoneRoutineSecret,
    vaultCosignerPriv: prov,
    arkadePriv: arkade,
    phoneRoutineBip340PubHex: bytesToHex(secp256k1.getPublicKey(phoneRoutineSecret, true)),
    vaultCosignerPub: bytesToHex(vaultCosignerPub),
    arkadePub: bytesToHex(arkadePub),
    leafHash,
    phoneRoutineBip340Pub,
  };
}

function authorizeWith(submitted, signerPriv, leafHash = null, signature = null) {
  const tx = parsePSBT(submitted);
  const hash = leafHash || tapLeafHash(tx);
  const sig = signature || schnorr.sign(preimageWitnessV1Msg(tx), signerPriv);
  tx.updateInput(0, {
    tapScriptSig: [[{ pubKey: schnorr.getPublicKey(signerPriv), leafHash: hash }, sig]],
  }, true);
  return bytesToB64(tx.toPSBT());
}

function authorizeWithBoth(
  submitted,
  vaultCosignerPriv,
  arkadePriv,
  vaultCosignerLeafHash = null,
  vaultCosignerSignature = null,
  arkadeLeafHash = null,
  arkadeSignature = null,
) {
  const vaultSigned = authorizeWith(submitted, vaultCosignerPriv, vaultCosignerLeafHash, vaultCosignerSignature);
  return authorizeWith(vaultSigned, arkadePriv, arkadeLeafHash, arkadeSignature);
}

function validatePair(pair, authorizedB64 = pair.authorized, overrides = {}) {
  return validateAuthorizedPSBT({
    submittedB64: pair.submitted,
    authorizedB64,
    phoneRoutineBip340PubHex: pair.phoneRoutineBip340PubHex,
    tweakedVaultCosignerXOnly: pair.vaultCosignerPub,
    tweakedArkadeCosignerXOnly: pair.arkadePub,
    ...overrides,
  });
}

test("authorized validation accepts exactly two pinned signer additions in either order", () => {
  const pair = authorizedPair();
  const verified = validateAuthorizedPSBT({
    submittedB64: pair.submitted,
    authorizedB64: pair.authorized,
    phoneRoutineBip340PubHex: pair.phoneRoutineBip340PubHex,
    tweakedVaultCosignerXOnly: pair.vaultCosignerPub,
    tweakedArkadeCosignerXOnly: pair.arkadePub,
  });
  expect(verified.vaultCosignerPub).toBe(pair.vaultCosignerPub);
  expect(verified.arkadeCosignerPub).toBe(pair.arkadePub);
  expect(verified.transactionId).toMatch(/^[0-9a-f]{64}$/);
  const expectedTxid = bytesToHex(Uint8Array.from(sha256(sha256(parsePSBT(pair.authorized).toBytes(true, false)))).reverse());
  expect(verified.transactionId).toBe(expectedTxid);

  const reversed = parsePSBT(pair.authorized);
  reversed.inputs[0].tapScriptSig.reverse();
  expect(validatePair(pair, bytesToB64(reversed.toPSBT())).transactionId).toBe(expectedTxid);
});

test("authorized validation rejects a response missing either routine cosigner", () => {
  const pair = authorizedPair();
  expect(() => validateAuthorizedPSBT({
    submittedB64: pair.submitted,
    authorizedB64: authorizeWith(pair.submitted, pair.vaultCosignerPriv),
    phoneRoutineBip340PubHex: pair.phoneRoutineBip340PubHex,
    tweakedVaultCosignerXOnly: pair.vaultCosignerPub,
    tweakedArkadeCosignerXOnly: pair.arkadePub,
  })).toThrow(/PhoneRoutineBIP340, VaultCosigner, and ArkadeCosigner/);
  expect(() => validatePair(pair, authorizeWith(pair.submitted, pair.arkadePriv)))
    .toThrow(/PhoneRoutineBIP340, VaultCosigner, and ArkadeCosigner/);
});

test("authorized validation rejects forged VaultCosigner and ArkadeCosigner signatures", () => {
  const pair = authorizedPair();
  const forged = new Uint8Array(64).fill(1);
  expect(() => validatePair(pair, authorizeWithBoth(
    pair.submitted, pair.vaultCosignerPriv, pair.arkadePriv, null, forged,
  ))).toThrow(/VaultCosigner signature invalid/);
  expect(() => validatePair(pair, authorizeWithBoth(
    pair.submitted, pair.vaultCosignerPriv, pair.arkadePriv, null, null, null, forged,
  ))).toThrow(/ArkadeCosigner signature invalid/);
});

test("authorized validation rejects substituted and duplicate signer roles", () => {
  const pair = authorizedPair();
  const attacker = hex32(9);
  expect(() => validatePair(pair, authorizeWithBoth(pair.submitted, attacker, pair.arkadePriv)))
    .toThrow(/duplicate or substituted/);

  const duplicate = parsePSBT(pair.authorized);
  const duplicateEntries = duplicate.inputs[0].tapScriptSig;
  const arkadeEntry = duplicateEntries.find(([meta]) => bytesToHex(meta.pubKey) === pair.arkadePub);
  arkadeEntry[0].pubKey = schnorr.getPublicKey(pair.vaultCosignerPriv);
  arkadeEntry[0].leafHash = new Uint8Array(32).fill(0xff);
  expect(() => validatePair(pair, bytesToB64(duplicate.toPSBT())))
    .toThrow(/duplicate or substituted/);

  expect(() => validatePair(pair, pair.authorized, { tweakedArkadeCosignerXOnly: pair.vaultCosignerPub }))
    .toThrow(/keys must be independent/);
});

test("authorized validation rejects 65-byte PhoneRoutineBIP340, VaultCosigner, and ArkadeCosigner signatures", () => {
  const pair = authorizedPair();
  const phoneRoutine65 = parsePSBT(pair.submitted);
  const phoneRoutineEntry = phoneRoutine65.inputs[0].tapScriptSig[0];
  phoneRoutine65.inputs[0].tapScriptSig = [[phoneRoutineEntry[0], Uint8Array.from([...phoneRoutineEntry[1], 1])]];
  const submitted65 = bytesToB64(phoneRoutine65.toPSBT());
  expect(() => validateAuthorizedPSBT({
    submittedB64: submitted65,
    authorizedB64: authorizeWithBoth(submitted65, pair.vaultCosignerPriv, pair.arkadePriv),
    phoneRoutineBip340PubHex: pair.phoneRoutineBip340PubHex,
    tweakedVaultCosignerXOnly: pair.vaultCosignerPub,
    tweakedArkadeCosignerXOnly: pair.arkadePub,
  })).toThrow(/PhoneRoutineBIP340 signature must be 64 bytes/);

  const vaultCosignerTx = parsePSBT(pair.submitted);
  const sig65 = Uint8Array.from([...schnorr.sign(preimageWitnessV1Msg(vaultCosignerTx), pair.vaultCosignerPriv), 1]);
  expect(() => validatePair(pair, authorizeWithBoth(
    pair.submitted, pair.vaultCosignerPriv, pair.arkadePriv, null, sig65,
  ))).toThrow(/VaultCosigner signature must be 64 bytes/);

  const arkadeSig65 = Uint8Array.from([...schnorr.sign(preimageWitnessV1Msg(vaultCosignerTx), pair.arkadePriv), 1]);
  expect(() => validatePair(pair, authorizeWithBoth(
    pair.submitted, pair.vaultCosignerPriv, pair.arkadePriv, null, null, null, arkadeSig65,
  ))).toThrow(/ArkadeCosigner signature must be 64 bytes/);
});

test("authorized validation rejects either signer on the wrong leaf", () => {
  const pair = authorizedPair();
  const wrongLeaf = new Uint8Array(32).fill(7);
  expect(() => validatePair(pair, authorizeWithBoth(
    pair.submitted, pair.vaultCosignerPriv, pair.arkadePriv, wrongLeaf,
  ))).toThrow(/VaultCosigner signature leaf/);
  expect(() => validatePair(pair, authorizeWithBoth(
    pair.submitted, pair.vaultCosignerPriv, pair.arkadePriv, null, null, wrongLeaf,
  ))).toThrow(/ArkadeCosigner signature leaf/);
});

test("authorized validation rejects mutation of the existing PhoneRoutineBIP340 tuple", () => {
  const pair = authorizedPair();
  const tx = parsePSBT(pair.authorized);
  const [meta, sig] = tx.inputs[0].tapScriptSig[0];
  tx.inputs[0].tapScriptSig[0] = [meta, Uint8Array.from(sig.map((b, i) => i === 0 ? b ^ 1 : b))];
  expect(() => validatePair(pair, bytesToB64(tx.toPSBT())))
    .toThrow(/mutated the PhoneRoutineBIP340 signature|routine signature delta/);
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
