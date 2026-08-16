# Arkade 2FA Vault — package notes

Repository landing page: [../../README.md](../../README.md). This file is
the trust-boundary and runbook detail for `poc/2fa-vault`.

Go authorization harness plus a localhost browser page. Open **only**
`http://localhost:8787` (RP ID and Origin are `localhost`). The compose
stack binds the host port as `127.0.0.1:8787`, but the page URL must still
be `http://localhost:8787` or WebAuthn/origin checks fail.

## What is implemented

- Operational / Savings Taproot trees (`ark-lib` closures, NUMS internal key)
- Provider HTTP API that calls Emulator `SubmitOnchainTx` only as a private client
- WebAuthn challenge/origin/RP/UV checks and the spending budget live in ordinary provider Go only. The WebAuthn credential ES256 public key is stored and used only for that off-chain check
- Arkade CSFS is `OP_0 OP_SIGHASH <0x11||directP256> OP_CHECKSIGFROMSTACK`. The committed key is a second, PRF-derived direct-auth P-256 public key (`HKDF-SHA256` info `arkade-2fa-vault/direct-p256/v1` || `uint32be(counter)`, rejection-sampled). The packet witness is only the compact low-S 64-byte signature over the current Arkade sighash
- SQLite UTC-day budget: reservation is committed before the external signer is invoked; completion is a second transaction. A crash after Sign can leave a usable PSBT while the row stays reserved. Do not treat that as crash-atomic pairing of signature and completed accounting
- Enrollment is **local TOFU / no attestation / setup authorization**: the first successful register is trusted on this origin. There is no authenticator attestation and no independent setup ceremony. `/v1/register` is idempotent only for that exact enrolled tuple (credential ID, WebAuthn P-256, DirectP256, hot pub); any other retry stays locked. The browser stages the complete encrypted local record under a pending `localStorage` key before `POST /register`, pins the resulting tweaked provider x-only key, and promotes the record only after success (and retries that exact tuple on reload if pending exists and the main record does not). The vault is built from the **browser-generated hot pubkey** and the provider persists the immutable descriptor (hot, offline, provider base, tweaked provider, **both** P-256 pubs, template/policy/network, CSV, addresses)
- The second-signer pub is a **public deterministic fixture** (`OfflinePubHex` = secp256k1 generator **G**, discrete log **1**). It is not custody or offline-key security. Savings has no provider key. This POC does not implement an offline generation/storage/signing ceremony
- Restart rebuilds trees from that stored record. A signer rotation or CSV/network/template change is refused unless the enrolled provider base is the current emulator key or listed as deprecated; the expected tweaked key always comes from the stored record
- Browser page: register PRF passkey (enrolls WebAuthn P-256 **and** distinct direct-auth P-256) → draft → preflight → `credentials.get` → PRF-derive direct key → sign the Arkade digest → bind (assertion stays off-chain; packet gets only `directSig`) → locally validate the bound PSBT → BIP342 hot-sign → authorize
- Same-origin vendored `@noble/curves@1.8.1` (`secp256k1` + `p256`) and `@scure/btc-signer@1.6.0` (see `web/vendor/NOTICE.md`); CSP blocks remote `script-src` / `connect-src`. That only stops a third-party CDN. It does not stop a compromised provider from serving modified first-party JS.

## What is not yet a complete E2E proof

Automated `go test ./poc/2fa-vault/...` still uses `webauthn.Synth` for
authorization paths. The dependency-free `web/e2e/capture.mjs` drives a
real Chrome virtual authenticator through CDP, requires a 32-byte PRF result
to remain inside the page, writes only the public ES256 assertion to
`testdata/webauthn_get.json`, and lets `TestBrowserAssertionFixture` verify
that assertion in Go. Run it with `make vault-browser-fixture` (set
`CHROME_BIN` when Chrome is not in a standard location). It proves the
browser WebAuthn/PRF primitive, but it does **not** yet drive the complete
draft → bind → authorize app flow. `make vault-browser-e2e` does drive that
full browser flow with a fresh Chrome virtual authenticator and checks the
exact register/bind/authorize request shapes. It deliberately starts
`cmd/provider -unsafe-local-signer`, fabricates an unmined previous
transaction, and stops after authorization; it is browser/app evidence, not
RemoteSigner, mempool, or confirmation evidence.

`-unsafe-local-signer` is test-only and does not prove the deployment boundary.
Compose deploys `cmd/provider`. `cmd/demo` is an optional local harness that
may keep fixture `hot.hex` / `offline.hex` on disk. That is not an
offline-key isolation demo.

## Same-origin client is an honest-code assumption

The provider currently serves the browser signer (`web/index.html`,
`web/app.js`, `web/vendor/*`) from the same origin as the API. If that
host is compromised, it can ship modified self-origin JavaScript. CSP and
local vendoring do not stop that code from reading the PRF result, the
decrypted hot key, or the signed PSBT and sending them to the attacker.
That collapses the hot factor into the provider factor.

This demo therefore assumes an honest, reproducible client. It does **not**
prove tolerance of a compromised provider. The intended separation is to
distribute or host the signing client independently (or as a native
reproducible app) and pin the provider API/origin. That is not what this
same-origin stack demonstrates.

The honest client also **trusts provider-supplied vault data**. Status
supplies the Operational script and address, not a full descriptor.
Preflight returns the Arkade challenge the passkey and DirectP256 key
sign; the browser does **not** independently recompute that Arkade
sighash. After Review, any change to destination, amount, fee, or
prevout invalidates the review (no silent re-draft). Bind still checks
the bound PSBT against the reviewed draft. Before Publish, the browser
checks that the authorized PSBT equals the submitted hot-signed PSBT
except exactly one extra 64-byte tapscript signature under the locally
pinned tweaked provider key; it verifies both the preserved hot signature
and the new provider signature over the exact BIP342 digest. Other PSBT
metadata changes are rejected. This is still a POC limit, not a full
independent-descriptor verification claim.

## Direct-auth script is transaction-bound; budget is not

The committed Arkade script is:

```
OP_0 OP_SIGHASH <0x11||directP256> OP_CHECKSIGFROMSTACK
```

`directP256` is **not** the WebAuthn credential public key. Enrollment
persists two distinct compressed P-256 pubs. The credential ES256 pub is
used only by `webauthn.Validate` on `/bind` and `/authorize`. The
PRF-derived direct-auth pub is what `AuthorizationScript` commits.

The packet witness is a single compact low-S 64-byte signature over the
current Arkade sighash. `clientDataJSON`, `authenticatorData`, and the
WebAuthn credential key must not appear in the serialized L1 packet.
`TestDirectP256AuthorizationIsTransactionBoundAndKeepsWebAuthnOffChain`
and `TestLocalSignerRejectsCapturedAssertionOnADifferentTransaction`
require that a signature copied from spend A fail on spend B at the raw
LocalSigner / Arkade VM — not only at the public HTTP boundary.

This POC still does **not** prove that the provider cosigner is bound to
WebAuthn semantics or the spending budget. Origin, RP ID, UV/UP and period
caps exist only in ordinary provider Go. Raw `SubmitOnchainTx` will still
sign a policy-violating transaction that already carries a valid direct
signature and hot signature.
`TestKnownTrustBoundaryRawSignerDoesNotEnforceProviderSpendingPolicy`
keeps that green on purpose.

Closing the remaining gap requires moving budget/WebAuthn state into the
key-constrained signer. Hiding gRPC does not close that gap.

## On-chain Arkade packet

The packet is an `OP_RETURN` ARK extension output on the Bitcoin
transaction that is broadcast. It now carries only the 64-byte direct-auth
signature plus the committed script. It is not a private sidecar, but it
is no longer a public WebAuthn replay token.

`TestArkadePacketOnchainPolicy` measures a finalized collaborative spend.

**Compatibility.** The ~117-byte packet exceeds Bitcoin Core's pre-v30
83-byte `datacarriersize` default. After Nigiri RPC is ready,
`regtest-up.sh` reads raw JSON with
`docker exec bitcoin bitcoin-cli getnetworkinfo` (not `nigiri rpc`, which
ANSI-colors through aurora) and fails unless `version` is numeric and
`>= 300000` (Core 30+). Current Nigiri/Core 30 defaults
`-datacarriersize=100000` and will usually relay the packet. There is no
`BITCOIN_EXTRA_ARGS` override; Nigiri does not consume it. Publication
still calls `testmempoolaccept` before `sendrawtransaction` — that is the
authoritative custom-policy gate (Knots and other peers may still reject
`datacarrier` / `scriptpubkey`). The live subtest funds the Operational
address and calls `testmempoolaccept` / `sendrawtransaction` when Nigiri
is reachable; it skips otherwise.

**Fee.** The packet is still the dominant extra output. The POC feerate
ceiling is 10 sat/vB with a 5 000 sat absolute cap so the two limits are
independently reachable. 50 sat/vB behind a 5 000 sat absolute cap is not
a coherent pair on this template.

**Privacy.** The on-chain witness no longer publishes the passkey
assertion. The preflight/bind HTTP conversation still can. Do not treat
the provider HTTP path as metadata-private.

## Run

**REGTEST ONLY — NEVER FUND WITH REAL BTC.** `VAULT_OFFLINE_PUB` /
`OfflinePubHex` is secp256k1 generator **G** with publicly known scalar
**1**. That is a public deterministic second-signer fixture for this
demo. It is not an opaque key and not custody or offline security.
Anyone who can spend a UTXO locked to this fixture can take the coins.

Pin Go `1.26.6` and Emulator `66fd93cd`.

`docker-compose.regtest.yml` **publishes** emulator `:7073` and puts every
service on the shared external `nigiri` network. That file is the generic
Emulator/Nigiri harness. It is **not** a private signer boundary.

The POC overlay creates an **internal** `vault-signer` compose network
(Compose project-scopes the Docker name; it is not a global network
another stack can join by name), forces the Emulator off `nigiri` onto
only that network, and attaches `arkd` plus `vault-provider` to it so
`EMULATOR_ARKD_URL` and `VAULT_EMULATOR` still resolve. `vault-provider` also stays on default/`nigiri` for Bitcoin RPC.
Host publishes from the ark support services are reset; the only published
port is `127.0.0.1:8787`. The image builds **`cmd/provider`**
(`vault-provider`). The second-signer pub in `VAULT_OFFLINE_PUB` is the
public generator-G fixture above, not a secret. Hot is enrolled by the
browser. SQLite persists on the
named volume `vault-provider-data`; `make vault-demo-down` keeps that volume.

Run the merge from this repository root: overlay `build.context` is `.`
because Compose resolves relative paths from the first `-f` file.

```bash
# From this repository root (requires docker, docker compose, nigiri, curl):
make vault-demo
# Open http://localhost:8787
make vault-demo-down

# Independent browser primitive check (Chrome + Bun; no Playwright):
make vault-browser-fixture

# Full browser app ceremony with the explicitly unsafe local test signer:
make vault-browser-e2e

# Opt-in full proof: Chrome PRF -> RemoteSigner -> confirmed regtest tx.
# Requires a clean POC container namespace; it never deletes Nigiri data.
VAULT_LIVE_ACCEPTANCE=1 make vault-regtest-e2e
```

`vault-regtest-e2e` is the machine-checked golden path. It uses a unique
Compose project and fresh provider volume, refuses to touch an existing POC
stack, and drives the real browser through enrollment, funded Operational
prevout, review, DirectP256 binding, hot signing, RemoteSigner authorization,
challenge-only publication, mining, and confirmation. It then restarts only
`vault-provider` and requires the same descriptor, completed challenge/txid,
20,500-sat economic outflow, and confirmation to survive before independently
querying Bitcoin Core for the exact txid. The browser derives that txid from
the verified authorized PSBT, and the run requires exactly one RemoteSigner
response that passed the Provider's exact-delta verification. Cleanup removes only that unique
acceptance project and volume; shared Nigiri containers and data remain.

The live command is deliberately opt-in and requires Docker, Docker Compose,
Nigiri, Bun, Chrome, and Core 30+. It is not run by ordinary unit tests.

`scripts/regtest-up.sh` is a detached launcher: it polls Nigiri
`getblockchaininfo` (bitcoind can fail that briefly while warming)
before treating RPC as absent, then either reuses it or starts
`nigiri start --ci --ark=false --liquid=false --ln=false` and polls
again. After RPC is ready it reads raw
`docker exec bitcoin bitcoin-cli getnetworkinfo` and fails unless the
node version is numeric and `>= 300000` (Core 30+), because the packet
does not fit the old 83-byte default. If start says Nigiri is already
running while RPC stays down, the launcher fails with a stale/warming
message and does not stop or delete user Nigiri state. It refuses to run
beside an official Nigiri
`ark` container, validates the merged compose, `up -d --build`, polls
the arkd v0.9.13 admin status, and makes its disposable operator wallet
initialized, unlocked, and synced before polling `/health`. Fresh stacks create
the wallet; reruns and restarts only unlock it when needed. The fixed default
password (`arkade-regtest-only-wallet-fixture`) is a public REGTEST-only fixture,
not a secret. `ARKD_REGTEST_WALLET_PASSWORD` may override it for this launcher.
The create command's mnemonic output is suppressed, every wallet admin command
has a timeout, and the readiness poll has a finite attempt limit. The launcher
then runtime-asserts the
Emulator has no host port, is not on `nigiri`, has exactly one attached
network, and that network is `Internal=true`. The provider uses **RemoteSigner only**. `VAULT_DEMO=1` enables
fund/mine only. After `/v1/demo/fund` the browser requires
`confirmations >= 1` before accepting the prevout. After a demo publish
that returns zero confirmations the browser mines once, queries
`GET /v1/tx?challenge=` once, and requires the exact txid and at least
one confirmation. Owner-path leaves remain in the vault
trees and ordinary Go tests; there is no owner-draft or owner-complete
HTTP. `POST /v1/publish` takes only the Arkade challenge and loads the
ledger's completed PSBT; it never broadcasts a client-supplied
transaction.

Savings status reports `savingsExcludesProvider` from leaf inspection.

`cmd/demo` is an **optional local harness only**. It may write fixture
`hot.hex` / `offline.hex` under `-data`. Do not deploy it.

A stale `*.sqlite` from an earlier POC schema is rejected; delete the file
and restart. There is no silent ALTER. The current schema stores the full
vault descriptor, not just the passkey and hot pubkey.

```bash
go test ./poc/2fa-vault/...
# Live docker compose config/build (optional):
VAULT_TEST_DOCKER=1 go test ./poc/2fa-vault/ -run TestVaultComposeOverlay

# Optional local harness (not the compose image):
go run ./poc/2fa-vault/cmd/demo -web poc/2fa-vault/web -emulator emulator:7073
```
