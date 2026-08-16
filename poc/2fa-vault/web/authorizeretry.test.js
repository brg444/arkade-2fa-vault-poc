import { expect, test } from "bun:test";
import { createAuthorizeRetryState } from "./authorizeretry.js";

const reviewKey = JSON.stringify({ prevout: "aa:0", amount: "20000", fee: "500" });
const challengeHex = "ab".repeat(32);
const expectedTxid = "cd".repeat(32);

function requestBody() {
  return {
    psbt: "exact-phoneRoutineSecret-and-direct-signed-psbt",
    credentialId: "01",
    clientDataJSON: "02",
    authenticatorData: "03",
    signature: "04",
  };
}

function validation() {
  return {
    submittedB64: "exact-phoneRoutineSecret-and-direct-signed-psbt",
    phoneRoutineBip340PubHex: "02" + "11".repeat(32),
    tweakedVaultCosignerXOnly: "22".repeat(32),
    tweakedArkadeCosignerXOnly: "33".repeat(32),
  };
}

test("transient authorize retry reuses the byte-identical serialized request body", async () => {
  const state = createAuthorizeRetryState();
  const first = state.stage(reviewKey, requestBody(), validation(), challengeHex);
  const sent = [];
  const post = async (pending, fail) => {
    sent.push(pending.bodyJSON);
    if (fail) throw new Error("public signer timeout");
    return { signedPsbt: "completed" };
  };

  await expect(post(first, true)).rejects.toThrow(/timeout/);
  const retry = state.pendingFor(reviewKey);
  await post(retry, false);
  expect(retry).toBe(first);
  expect(sent).toHaveLength(2);
  expect(sent[1]).toBe(sent[0]);
  expect(sent[0]).toBe(JSON.stringify(requestBody()));
});

test("successful authorization drops assertion and PSBT material before publish retry state", () => {
  const state = createAuthorizeRetryState();
  state.stage(reviewKey, requestBody(), validation(), challengeHex);
  const completed = state.markAuthorized(reviewKey, {
    challengeHex,
    expectedTxid,
    replay: false,
  });

  expect(state.pendingFor(reviewKey)).toBeNull();
  expect(completed).toEqual({ reviewKey, challengeHex, expectedTxid, replay: false });
  const retained = JSON.stringify(state.completedFor(reviewKey));
  for (const secret of ["psbt", "clientDataJSON", "authenticatorData", "signature", "submittedB64"]) {
    expect(retained).not.toContain(secret);
  }
});

test("intent change clears pending sensitive material while an identical review retains it", () => {
  const state = createAuthorizeRetryState();
  const pending = state.stage(reviewKey, requestBody(), validation(), challengeHex);
  expect(state.clearUnless(reviewKey)).toBe(false);
  expect(state.pendingFor(reviewKey)).toBe(pending);

  const changed = JSON.stringify({ prevout: "aa:0", amount: "20001", fee: "500" });
  expect(state.clearUnless(changed)).toBe(true);
  expect(state.pendingFor(reviewKey)).toBeNull();
  expect(state.completedFor(reviewKey)).toBeNull();
});
