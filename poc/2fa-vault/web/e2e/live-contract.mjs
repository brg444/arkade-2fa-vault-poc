export function auditLiveRequests(requests, challenge) {
  const expected = new Map([
    ["/v1/register", ["credentialId", "phoneDirectP256", "phoneRoutineBip340Pub", "webauthnP256"]],
    ["/v1/demo/fund", ["amount"]],
    ["/v1/draft", ["fee", "prevTxHex", "recipientAmount", "recipientScript", "vout"]],
    ["/v1/preflight", ["psbt"]],
    ["/v1/bind", ["authenticatorData", "clientDataJSON", "credentialId", "directSig", "psbt", "signature"]],
    ["/v1/authorize", ["authenticatorData", "clientDataJSON", "credentialId", "psbt", "signature"]],
    ["/v1/publish", ["challenge"]],
    ["/v1/demo/mine", ["blocks"]],
  ]);
  for (const [path, fields] of expected) {
    const matches = requests.filter((request) => request.path === path);
    if (matches.length !== 1) throw new Error(`${path} request count = ${matches.length}, want 1`);
    const got = Object.keys(matches[0].body).sort();
    if (JSON.stringify(got) !== JSON.stringify(fields)) {
      throw new Error(`${path} fields = ${JSON.stringify(got)}, want ${JSON.stringify(fields)}`);
    }
  }
  const unexpected = requests.filter((request) => !expected.has(request.path));
  if (unexpected.length) throw new Error(`unexpected mutation request: ${unexpected[0].path}`);
  const body = (path) => requests.find((request) => request.path === path).body;
  if (Number(body("/v1/demo/fund").amount) !== 100_000) throw new Error("unexpected demo funding amount");
  if (Number(body("/v1/draft").recipientAmount) !== 20_000 || Number(body("/v1/draft").fee) !== 500) {
    throw new Error("unexpected reviewed economic outflow");
  }
  if (Number(body("/v1/demo/mine").blocks) !== 1) throw new Error("demo must mine exactly one block");
  const publish = body("/v1/publish");
  if (publish.challenge !== challenge || !/^[0-9a-f]{64}$/.test(publish.challenge)) {
    throw new Error("publish was not bound to the reviewed Arkade challenge");
  }
  const forbidden = new Set([
    "prf", "scalar", "privatekey", "privatekeyhex", "phoneroutineprivate", "externalownerprivate",
    "kek", "ciphertext", "nonce", "rawtx", "rawtransaction",
  ]);
  const walk = (value) => {
    if (!value || typeof value !== "object") return;
    for (const [key, child] of Object.entries(value)) {
      if (forbidden.has(key.toLowerCase())) throw new Error(`forbidden API field: ${key}`);
      walk(child);
    }
  };
  for (const request of requests) walk(request.body);
}

export function validateLiveState({ browserResult, tx, status, finalDemo }) {
  if (!/^[0-9a-f]{64}$/.test(browserResult.challenge || "")) throw new Error("invalid Arkade challenge");
  if (!/^[0-9a-f]{64}$/.test(browserResult.expectedTxid || "") || browserResult.txid !== browserResult.expectedTxid) {
    throw new Error("published txid does not match the browser-authorized PSBT");
  }
  if (tx.txid !== browserResult.txid || Number(tx.confirmations) < 1) {
    throw new Error("challenge status does not identify the confirmed browser transaction");
  }
  if (!status.enrolled || Number(status.periodSpent) !== 20_500 || Number(status.periodRemaining) !== 79_500) {
    throw new Error(`unexpected live budget state: ${JSON.stringify(status)}`);
  }
  if (browserResult.replay !== false) throw new Error("fresh authorization was reported as a replay");
  if (finalDemo.signerMode !== "remote" || Number(finalDemo.remoteSignerSuccesses) !== 1) {
    throw new Error(`expected exactly one verified RemoteSigner response: ${JSON.stringify(finalDemo)}`);
  }
  return {
    challenge: browserResult.challenge,
    txid: browserResult.txid,
    confirmations: Number(tx.confirmations),
    replay: browserResult.replay,
    periodSpent: Number(status.periodSpent),
    periodRemaining: Number(status.periodRemaining),
    operationalAddress: status.operationalAddress,
    operationalScript: status.operationalScript,
    remoteSignerSuccesses: Number(finalDemo.remoteSignerSuccesses),
  };
}
