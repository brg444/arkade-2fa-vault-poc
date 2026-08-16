# Arkade 2FA Vault — trust boundary and test notes

Repository landing page: [../../README.md](../../README.md). Mutinynet
operations are documented in [deploy/mutinynet/README.md](deploy/mutinynet/README.md).
The numbered response to all 41 independent Prem findings is in
[docs/prem-security-report-disposition.md](docs/prem-security-report-disposition.md).

This package implements an ordinary L1 Taproot vault, not an Ark VTXO. It has
two deliberately separate profiles:

- **Regtest demonstration:** `cmd/provider` plus two independent private
  Emulator instances (private Provider and Arkade cosigner), browser
  automation, funding, mining, and restart checks. The backup key is the
  public generator-G fixture and provides no custody.
- **Mutinynet software authorizer:** `cmd/authorizer` owns the file-backed
  provider private key and authoritative SQLite ledger in one process. A
  stateless Caddy gateway serves the POC client and forwards only explicitly
  allowlisted policy operations. The authorizer has one narrow outbound HTTPS
  client to the release-pinned public Arkade Emulator cosigner. It exposes no
  inbound Emulator/generic signing route, gRPC/arkd signer transport, raw
  signing RPC, static files, or demo route.

Neither profile is for real BTC. The Mutinynet profile is hardened Docker
process isolation, not an enclave, HSM, or production custody boundary.

## Cryptographic model

The Operational tree has three paths:

1. exact 3-of-3 hot secp256k1 + tweaked private Provider secp256k1 +
   tweaked public Arkade Emulator secp256k1;
2. hot secp256k1 + independent backup secp256k1; and
3. CSV delay + independent backup secp256k1.

Both collaborative tweaks are derived from their independent base keys with
the same `ArkadeScriptHash`. Savings has only the owner and longer-CSV backup
paths; both signer roles' base and tweaked keys are absent from every Savings
leaf.

The collaborative Arkade authorization script is:

```text
OP_0 OP_SIGHASH <0x11||directP256> OP_CHECKSIGFROMSTACK
```

Enrollment stores two distinct P-256 public keys:

- the WebAuthn ES256 credential key, used only off-chain to verify the exact
  challenge, stored origin/RP ID, UP, and UV; and
- `DirectP256`, derived from the passkey PRF with a domain-separated
  rejection-sampled HKDF construction and committed in the script above.

The DirectP256 key signs the current Arkade sighash. Only its compact low-S
64-byte signature appears in the on-chain packet. `clientDataJSON` and
`authenticatorData` never enter the Bitcoin transaction. A captured direct
signature from transaction A fails on transaction B at the Arkade VM itself.
The passkey does not sign Bitcoin.

The packet is a public OP_RETURN Ark extension output, not a private sidecar.
It no longer publishes the WebAuthn assertion, but preflight/bind traffic and
the public Arkade signing call still reveal transaction metadata. Do not treat
either HTTP path as private.

The browser creates a random secp256k1 hot key and encrypts it with a key
derived from the PRF result. The PRF bytes, DirectP256 scalar, and decrypted
hot scalar must never reach the authorizer.

All secp256k1 roles are checked by Taproot x-only identity, not compressed-key
parity. Hot, backup, private Provider base/tweak, and public Arkade Emulator
base/tweak identities must remain pairwise independent. Mutinynet rejects both
parities of the public generator-G fixture.

## What the authorizer verifies

`Service.Authorize` treats the request, PSBT, previous transaction, browser
assertion, public-cosigner response, and publisher response as hostile. Before
either cosigner result is accepted it independently verifies:

- exactly one supported Operational input and its full previous transaction;
- matching outpoint, WitnessUtxo, value, and enrolled Operational script;
- the exact collaborative tapscript, control block, and SIGHASH_DEFAULT;
- one reviewed native-SegWit recipient and optional exact Operational change;
- the canonical Arkade packet and transaction-bound DirectP256 signature;
- the hot BIP342 signature over the same transaction;
- an exact transaction-bound WebAuthn challenge plus origin/RP/UP/UV semantics;
- absolute fee, fee-rate, per-transaction, and UTC-period limits; and
- recipient plus miner fee as economic outflow.

The authorization script independently enforces the fixed transaction shape,
native-SegWit recipient/change placement, recursive Operational change, and
the exact canonical Ark extension script as the final zero-valued output. It
also enforces recipient and fee caps and the final 3-signature witness fee rate. DirectP256
remains the single Arkade packet witness and final `OP_SIGHASH` gate; it is not
a fourth collaborative tapscript signature.

WebAuthn origin/RP/UP/UV semantics and the UTC-period allowance remain ordinary
authorizer Go state, not on-chain constraints. Both regtest RemoteSigners and
the external public Arkade service are intentionally policy-agnostic. A public
Arkade signature alone cannot spend the 3-of-3 leaf, but exposing a generic
route to the private Provider key would bypass those off-chain checks. That is
why the Mutinynet claim depends on the in-process private signer plus the
explicit inbound allowlist; merely hiding a gRPC port would not establish it.

The immutable credential and descriptor row is authenticated with a
versioned, length-prefixed HMAC record. Its key is HKDF-SHA256-derived from
the file-only provider scalar and never stored in SQLite. Any missing MAC,
DB-only field mutation, or provider-key mismatch fails closed before stored
authentication or descriptor fields are used. This detects database drift;
it is not host-compromise or rollback protection.

The SQLite issuance state machine is:

```text
reserved(request_psbt)
  → provider_signed(request_psbt, provider_psbt)
  → completed(request_psbt, provider_psbt, signed_psbt)
```

The exact normalized browser PSBT and allowance
reservation are committed before the private Provider key is used. The private
signature is durably persisted before the stored Provider-signed PSBT is sent
to the public Arkade Emulator. An exact retry resumes the persisted stage,
skipping any signer whose result is already stored; a different PSBT with the
same witness-masked Arkade digest is rejected. Every state counts against the
allowance, ambiguous failures are never released, and an exact completed retry
returns the stored result without either signer.

`AuthorizerHandler` enumerates the complete key-owning HTTP surface. It never
delegates routing to a generic or demo mux:

| Method | Paths |
| --- | --- |
| GET | `/health`, `/v1/status`, `/v1/tx` |
| POST | `/v1/register`, `/v1/preflight`, `/v1/draft`, `/v1/bind`, `/v1/authorize`, `/v1/publish` |
| OPTIONS | the eight `/v1/*` paths above |

Known paths with a wrong method return 405; all other `/v1/*` paths return
404. `/v1/publish` accepts only a completed challenge and loads the stored
authorized PSBT. It never accepts a caller-supplied raw transaction. In
particular, the outbound public-cosigner path `/v1/onchain-tx` is not an
inbound authorizer or gateway route.

## Enrollment and restart state

Registration is one vault per isolated authorizer instance. It is idempotent
only for the exact enrolled tuple: credential ID, WebAuthn key, DirectP256 key,
hot key, backup key, both cosigner base/tweaked identities, public Arkade
Emulator origin/version, network, numeric policy, policy/template versions,
CSV delays, client origin, and RP ID. Any incompatible restart fails closed
rather than deriving a different address.

On Mutinynet, an empty ledger also requires a 32–256 byte bootstrap token from
a regular file. `/v1/register` must carry that token in
`X-Vault-Enrollment-Token`. Absent, incorrect, and replayed tokens fail. After
successful registration the in-memory hash is cleared, and subsequent
restarts neither read nor require the token file. The browser does not persist
the token; interrupted pending enrollment can be retried after re-entry.

This remains setup authorization without authenticator attestation or an
independent enrollment ceremony. The operator trusts the first token-authorized
tuple on the configured origin. The encrypted hot-key ciphertext, nonce, and
credential identifier stored for recovery remain readable to same-origin
JavaScript even though the hot scalar is encrypted.

The browser stages its complete encrypted local record before registration,
pins the returned private Provider tweak, the public Arkade Emulator
base/tweak/origin/version identity, and the separate vault network identity,
then promotes the record only after an exact successful commit. It verifies an
authorized response contains the submitted hot signature plus exactly the two
expected valid cosigner signatures, in either order, with no other mutation.

Immediately before `/v1/authorize`, the page serializes the exact request body
into page memory. If the public signer or network fails, another click in the
same unchanged page retries those identical bytes before any new WebAuthn,
DirectP256, or hot signing. Assertion/PSBT material is never written to browser
storage and is cleared after verified authorization or any intent change; a
non-sensitive challenge/txid receipt alone can survive long enough to retry
publication.

The current descriptor and issuance tables are a fail-closed v2 schema. Old
v1 databases are not auto-migrated, and UTXOs funded to the old 2-of-2 tree do
not become 3-of-3 outputs. Preserve the old keys/database and perform an
explicit reviewed spend/migration with compatible old software before using a
fresh v2 authorizer; never point the new binary at an old database expecting an
upgrade.

For a fresh Mutinynet enrollment, the release-pinned public base must be the
endpoint's current signer. On restart, an HMAC-authenticated existing
descriptor may keep its exact stored base/tweak while that base is actively
advertised as deprecated by the same pinned endpoint under an allowed release
version. Neither `GetInfo` nor a signing response can substitute or enroll a
new identity; disappearance of the stored key fails closed.

## Mutinynet deployment boundary

The base Compose topology has exactly two local services:

```text
browser -> TLS/static gateway -> internal-only authorizer
                                      |-> pinned HTTPS public Arkade Emulator
                                      `-> checkpoint-pinned HTTPS Esplora
```

- Only the authorizer mounts the provider-key secret and SQLite volume.
- Only the gateway publishes ports 80/443; the authorizer has no host port.
- Gateway-to-authorizer traffic uses an internal Docker network.
- Separate edge/egress networks are pinned as the default routes.
- Both containers are non-root, read-only, capability-free, PID-limited, and
  run with `no-new-privileges`.
- Caddy matches every API route by method, deletes the enrollment-token header
  from access logs, and serves only vendored same-origin assets.
- The public third-signer origin, compressed base key, and exact allowed
  version are constants in `internal/deployment/config.go`; Compose exposes no
  override. The HTTPS client rejects redirects and unbounded/non-JSON replies.
- Public Emulator `GetInfo` currently reports version and signer keys but no
  network identity. It is therefore not cryptographic Mutinynet attestation.
  The intended chain is established separately by the Esplora height-1
  checkpoint and code-pinned Mutinynet transaction/address parameters.
- The authorizer requires HTTPS Esplora without redirects and verifies the
  Mutinynet height-1 checkpoint. Generic `chain=signet` is insufficient.
- The built authorizer is tested to exclude the generic Emulator gRPC client,
  arkd discovery transport, environment-selected signer endpoints, and demo
  signing strings while requiring the narrow pinned HTTPS cosigner markers.
  Small `grpc/codes`-family utility packages remain transitively through
  ark-lib error types; they provide no client connection or transport surface.

The enrollment overlay alone mounts the one-time token. Normal restarts use
the base file. Real secret files belong outside the repository; `.gitignore`
and `.dockerignore` provide defense in depth.

See [the deployment runbook](deploy/mutinynet/README.md) for commands.

## Regtest demonstration

Open only `http://localhost:8787`; its RP ID and WebAuthn origin are
`localhost`. The stack binds `127.0.0.1:8787`, but opening the numeric-host URL
still fails origin/RP checks. The regtest backup key is secp256k1 generator G
with known scalar 1. It is a test fixture, not custody; anyone can use the
backup paths of a funded fixture vault. Pin Go `1.26.6` and Emulator
`66fd93cd` for the recorded evidence.

The repository's generic regtest base Compose can publish an Emulator and put
support services on the shared Nigiri network. It is not a signer boundary.
The vault overlay instead places both independent Emulator instances on
project-scoped internal signer networks, removes their host publishes, and
leaves only `127.0.0.1:8787` exposed. Run the Compose merge from the repository
root because relative build paths resolve from the first Compose file.

```bash
make vault-demo
make vault-demo-down

make vault-browser-fixture
make vault-browser-e2e
VAULT_LIVE_ACCEPTANCE=1 make vault-regtest-e2e
```

`vault-regtest-e2e` uses a unique Compose project, initializes or unlocks the
disposable arkd v0.9.13 wallet with a public regtest-only fixture password,
funds the Operational address, drives a real Chrome virtual authenticator,
binds DirectP256, adds the hot signature plus independent private-Provider and
Arkade-Emulator signatures, publishes, mines, restarts the provider, and checks
the exact confirmed txid and durable outflow. It refuses to alter shared Nigiri
data.

`vault-browser-fixture` proves only the Chrome WebAuthn/PRF primitive and writes
only a public assertion fixture. `vault-browser-e2e` drives the application
ceremony with the explicitly test-only `-unsafe-local-signer`, an unmined
fabricated prevout, and no RemoteSigner, mempool, or confirmation claim. Only
the opt-in `vault-regtest-e2e` covers both RemoteSigners, publication, mining,
restart, exact txid, and durable outflow. It requires Docker, Compose, Nigiri,
Bun, Chrome, and Core 30+; ordinary unit tests do not run it.

The launcher refuses to alter shared Nigiri data, refuses an official Nigiri
`ark` container, and uses finite wallet/readiness timeouts. Its fixed arkd
wallet password is a public regtest fixture, not a secret. Funding/mining
routes exist only with `VAULT_DEMO=1`; publication always accepts a completed
challenge and loads the stored PSBT, never caller-supplied transaction bytes.
`make vault-demo-down` retains the provider volume.

The launcher reads raw node JSON with
`docker exec bitcoin bitcoin-cli getnetworkinfo` and requires a numeric
Bitcoin Core version `>= 300000` (Core 30), because the current 274-byte Arkade
packet exceeds the old default datacarrier limit. It deliberately does not
parse ANSI-colored `nigiri rpc` output. Publication still runs
`testmempoolaccept` before broadcast; that is the authoritative local
custom-policy gate.

Both regtest `RemoteSigner` instances remain intentionally policy-agnostic.
That does not weaken the Mutinynet claim because `cmd/provider` rejects
non-regtest, Mutinynet Compose runs no local Emulator or inbound signer, and
the authorizer excludes the regtest gRPC/arkd remote-signing graph. Its separate
outbound public cosigner client is HTTPS, release-pinned, response-reconciled,
and reachable only after the private policy gate and durable stage.

## Browser trust limitation

The current gateway serves the signing JavaScript from the same origin as the
API. CSP and vendoring remove third-party runtime code, but a compromised
gateway can still serve modified first-party JavaScript that reads PRF output,
decrypted hot material, or a signed PSBT. The current browser independently
derives the restricted one-input Arkade sighash from its validated PSBT and
requires the provider preflight value to match exactly. It still consumes a
provider-supplied partial descriptor instead of deriving every tree byte from
a complete versioned public descriptor.

Therefore the POC still assumes an honest, reproducible client. The intended
next client is a dedicated Vault mode in an independently distributable
Arkade Wallet fork. It must derive and verify a versioned public descriptor,
PSBT, prevout, and scripts locally, while retaining cross-language sighash
parity. See
[docs/arkade-wallet-vault-mode.md](docs/arkade-wallet-vault-mode.md).

## Other explicit limits

- The real backup-key generation/storage/signing ceremony is out of scope.
- `cmd/demo` is an optional local harness that may write fixture `hot.hex` and
  `offline.hex` files. It is not the Compose image or an isolation proof; do
  not deploy it.
- One passkey and one vault per authorizer instance are supported.
- Policy caps remain code-pinned; only network, origin/RP ID, and CSV delays
  are runtime deployment inputs.
- The current 274-byte Arkade packet depends on a relay policy that accepts the larger
  OP_RETURN; Mutinynet does, while regtest requires Core 30+. Publication's
  `testmempoolaccept` result is the authoritative local custom-policy gate;
  other peers, including differently configured Knots nodes, may still reject
  the transaction.
- The packet dominates the extra output weight. The 10 sat/vB ceiling and
  5,000-sat absolute cap are separate limits and both must pass.
- Mutinynet publication uses Esplora; no public Bitcoin JSON-RPC is assumed.
- The public Arkade Emulator is an availability and transaction-privacy
  dependency. Its `GetInfo` does not attest network; the authorizer independently
  pins Mutinynet through Esplora height 1 and rejects every response mutation
  except its one expected signature.
- No attestation, multi-user account system, operator migration, mainnet
  support, or complete owner/recovery wallet ceremony is claimed.

## Tests

```bash
go test ./poc/2fa-vault/...
bun test poc/2fa-vault/web/*.test.js

# Optional resolved-Compose checks when Docker is available.
VAULT_TEST_DOCKER=1 go test ./poc/2fa-vault/ -run 'TestVaultComposeOverlay|TestMutinynetCompose'
```

The suite includes hermetic tests for every major module and boundary:
Taproot/key separation, WebAuthn parsing, P-256 signatures, browser PRF state,
network-specific address validation, PSBT/prevout correspondence, hot and
both cosigner signatures, fee/integer policy, staged exact-request reservations
and retries, bootstrap lifecycle, restart compatibility, public-cosigner
identity/response bounds, Esplora/RPC checkpointing and redirect rejection,
explicit route surfaces, secret parsing, hardened Compose ownership, and
authorizer dependency/binary boundary checks.
