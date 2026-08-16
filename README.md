# Arkade 2FA Vault POC

Demonstrable **L1 Taproot 2FA cosigning vault** on Arkade. A localhost
passkey authorizes a collaborative spend; a private Arkade Emulator
cosigns only after the Provider checks the bound transaction.

**REGTEST ONLY — NEVER FUND WITH REAL BTC.** The second-signer pub
(`VAULT_OFFLINE_PUB` / `OfflinePubHex`) is secp256k1 generator **G**
(scalar **1**). That is a public deterministic fixture, not custody.
Anyone who can spend a UTXO locked to it can take the coins.

Open **only** `http://localhost:8787` (WebAuthn RP ID and Origin are
`localhost`). Compose binds `127.0.0.1:8787`, but a `127.0.0.1` URL
fails origin checks.

This tree vendors [arkade-os/emulator](https://github.com/arkade-os/emulator)
at `66fd93cd` so the vault can call `SubmitOnchainTx` as a private
client. Emulator API and opcode docs live in [EMULATOR.md](EMULATOR.md).
Vault trust-boundary notes live in [poc/2fa-vault/README.md](poc/2fa-vault/README.md).

## What this is

Ordinary Bitcoin Taproot UTXOs, not Ark VTXOs.

| Vault | Leaves | Provider key |
| --- | --- | --- |
| Operational | hot + tweaked provider; hot + second signer; CSV + second signer | yes, collaborative leaf only |
| Savings | hot + second signer; longer CSV + second signer | never |

Collaborative authorization script:

```
OP_0 OP_SIGHASH <0x11||directP256> OP_CHECKSIGFROMSTACK
```

`directP256` is a PRF-derived P-256 key, **not** the WebAuthn credential
key. The on-chain packet witness is one compact low-S 64-byte signature
over the current Arkade sighash. WebAuthn `clientDataJSON` /
`authenticatorData` stay off-chain.

Flow: register PRF passkey → draft → preflight → `credentials.get` →
PRF-derive direct key → bind (assertion off-chain; packet gets only
`directSig`) → hot-sign → authorize → publish by challenge.

## Run

Pin Go `1.26.6`. Needs Docker, Docker Compose, Nigiri, curl. Chrome +
Bun for the browser proofs.

```bash
# Private emulator + provider UI (Nigiri + Core 30+)
make vault-demo
# Open http://localhost:8787
make vault-demo-down   # keeps the vault-provider-data volume

go test ./poc/2fa-vault/...

# Chrome virtual authenticator, PRF primitive only
make vault-browser-fixture

# Full browser ceremony with the test-only unsafe local signer
make vault-browser-e2e

# Opt-in golden path: Chrome PRF -> RemoteSigner -> confirmed regtest tx
VAULT_LIVE_ACCEPTANCE=1 make vault-regtest-e2e
```

`vault-regtest-e2e` is the machine-checked path: unique Compose project,
real browser enrollment, funded Operational prevout, DirectP256 bind,
hot sign, RemoteSigner authorize, challenge-only publish, mine, provider
restart, then Bitcoin Core confirmation of the same txid and 20,500-sat
outflow. It refuses to touch an existing POC stack and never stops or
deletes shared Nigiri data. Ordinary unit tests do not run it.

## Layout

```
poc/2fa-vault/          vault Provider, policy ledger, Taproot trees, WebAuthn, UI
poc/2fa-vault/web/      localhost passkey page (vendored noble/scure)
cmd/emulator.go         vendored Arkade signing oracle (not published to the host)
docker-compose.regtest.yml   generic emulator/Nigiri harness (not the private boundary)
poc/2fa-vault/docker-compose.yml   overlay: internal vault-signer net, :8787 only
```

The overlay creates an internal `vault-signer` network, takes the
emulator off `nigiri` and off every host port, and publishes only
`127.0.0.1:8787`. The image runs `poc/2fa-vault/cmd/provider`.
`cmd/demo` is an optional local harness — do not deploy it.

## What is implemented

- Operational / Savings trees (`ark-lib` closures, NUMS internal key)
- Provider HTTP API; Emulator `SubmitOnchainTx` is a private client only
- TOFU enrollment of WebAuthn P-256 **and** distinct DirectP256; vault
  built from the browser-generated hot pubkey; immutable descriptor in
  SQLite
- UTC-day budget (50k sat/tx, 100k sat/period, 5k sat / 10 sat/vB fee)
  reserved before the external signer is invoked
- Restart rebuilds trees from the stored record; signer/CSV/network/
  template drift is refused
- Same-origin CSP and vendored JS (blocks a CDN; does not survive a
  compromised provider serving modified first-party JS)

## What this does not prove

| Claim | Status |
| --- | --- |
| WebAuthn + period budget bind the provider key | **No.** They live in ordinary Provider Go. Raw `SubmitOnchainTx` still signs a policy-violating tx that already has a valid DirectP256 + hot signature. `TestKnownTrustBoundaryRawSignerDoesNotEnforceProviderSpendingPolicy` is green on purpose. |
| Compromised-provider resistance | **No.** The provider serves the signing page. Stolen JS can read the PRF result, hot key, and PSBT. |
| Independent client verification | **No.** The browser trusts the provider challenge; it does not recompute the Arkade sighash. |
| Offline / second-signer custody | **No.** The second key is generator G. There is no offline ceremony. |
| Crash-atomic budget + signature | **No.** A crash after Sign can leave a usable PSBT while the row stays reserved. |
| Production WebAuthn | **No.** Local TOFU, no attestation. Unit tests still use `webauthn.Synth`. |
| CI of the live path | **No.** `vault-regtest-e2e` is opt-in and local. Inherited emulator workflows fire only on `master` / PRs. |

Hiding gRPC does not close the policy-oracle gap. That requires moving
budget and WebAuthn state into the key-constrained signer.

Packet size needs Bitcoin Core 30+ (`datacarriersize`). Publication
still uses `testmempoolaccept` before broadcast.

## Tests

```bash
go test ./poc/2fa-vault/...
VAULT_TEST_DOCKER=1 go test ./poc/2fa-vault/ -run TestVaultComposeOverlay
```

| Target | What it proves |
| --- | --- |
| `go test ./poc/2fa-vault/...` | Go policy, trees, packet, HTTP boundary (synthetic WebAuthn) |
| `make vault-browser-fixture` | Real Chrome PRF / assertion primitive |
| `make vault-browser-e2e` | Full browser register → bind → authorize (`-unsafe-local-signer`) |
| `VAULT_LIVE_ACCEPTANCE=1 make vault-regtest-e2e` | RemoteSigner + confirmed regtest + restart durability |

## License / provenance

Vault code is under `poc/2fa-vault/`. The rest of the tree is the
pinned emulator snapshot; see [EMULATOR.md](EMULATOR.md) and
[SECURITY.md](SECURITY.md).
