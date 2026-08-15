import { expect, test } from "bun:test";
import { auditLiveRequests, validateLiveState } from "./e2e/live-contract.mjs";

const challenge = "ab".repeat(32);
const txid = "cd".repeat(32);

function requests() {
  return [
    { path: "/v1/register", body: { credentialId: "01", directP256: "02", hotPub: "03", webauthnP256: "04" } },
    { path: "/v1/demo/fund", body: { amount: 100000 } },
    { path: "/v1/draft", body: { fee: 500, prevTxHex: "00", recipientAmount: 20000, recipientScript: "51", vout: 0 } },
    { path: "/v1/preflight", body: { psbt: "draft" } },
    { path: "/v1/bind", body: { authenticatorData: "01", clientDataJSON: "02", credentialId: "03", directSig: "04", psbt: "draft", signature: "05" } },
    { path: "/v1/authorize", body: { authenticatorData: "01", clientDataJSON: "02", credentialId: "03", psbt: "signed", signature: "05" } },
    { path: "/v1/publish", body: { challenge } },
    { path: "/v1/demo/mine", body: { blocks: 1 } },
  ];
}

test("live request contract accepts only the canonical golden path", () => {
  expect(() => auditLiveRequests(requests(), challenge)).not.toThrow();
});

test("live request contract rejects changed values and publish fields", () => {
  const wrongAmount = requests();
  wrongAmount[2].body.recipientAmount = 20001;
  expect(() => auditLiveRequests(wrongAmount, challenge)).toThrow(/economic outflow/);

  const rawPublish = requests();
  rawPublish[6].body.rawTx = "00";
  expect(() => auditLiveRequests(rawPublish, challenge)).toThrow(/fields/);

  const duplicateAuthorize = requests();
  duplicateAuthorize.push({ ...duplicateAuthorize[5] });
  expect(() => auditLiveRequests(duplicateAuthorize, challenge)).toThrow(/request count/);
});

function state() {
  return {
    browserResult: { challenge, txid, expectedTxid: txid, replay: false },
    tx: { txid, confirmations: 1 },
    status: {
      enrolled: true,
      periodSpent: 20500,
      periodRemaining: 79500,
      operationalAddress: "bcrt1ptest",
      operationalScript: "5120" + "11".repeat(32),
    },
    finalDemo: { signerMode: "remote", remoteSignerSuccesses: 1 },
  };
}

test("live result contract binds browser txid, RemoteSigner and confirmation", () => {
  const valid = state();
  expect(validateLiveState(valid)).toEqual({
    challenge,
    txid,
    confirmations: 1,
    replay: false,
    periodSpent: 20500,
    periodRemaining: 79500,
    operationalAddress: valid.status.operationalAddress,
    operationalScript: valid.status.operationalScript,
    remoteSignerSuccesses: 1,
  });

  const providerSwap = state();
  providerSwap.browserResult.txid = "ef".repeat(32);
  expect(() => validateLiveState(providerSwap)).toThrow(/browser-authorized PSBT/);

  const noRemote = state();
  noRemote.finalDemo.remoteSignerSuccesses = 0;
  expect(() => validateLiveState(noRemote)).toThrow(/RemoteSigner/);

  const unconfirmed = state();
  unconfirmed.tx.confirmations = 0;
  expect(() => validateLiveState(unconfirmed)).toThrow(/confirmed/);
});
