# Arkade 2FA Vault POC

Demonstrable **L1 Taproot 2FA cosigning vault** on Arkade. A passkey
ceremony authorizes a transaction, a separate PRF-derived P-256 key signs the
Arkade transaction digest, and the hot key plus two independently tweaked
cosigners produce the exact three-signature Taproot spend.

This is a proof of concept for non-mainnet funds. The Mutinynet deployment is
a hardened software process, not an enclave, HSM, or production custody
system. Never fund it with real BTC.

## Two execution profiles

| Profile | Purpose | Provider-key boundary |
| --- | --- | --- |
| Regtest | Reproducible local browser, two independent Emulators, mining, and restart demo | `cmd/provider` calls private Provider and Arkade signer fixtures; backup is public scalar 1 |
| Mutinynet | Internet-deployable POC | `cmd/authorizer` alone owns the private Provider key and SQLite ledger; it then calls one release-pinned public Arkade cosigner through narrow outbound HTTPS |

The Mutinynet topology contains no generic/gRPC signer client, generic signing
RPC, demo funding/mining route, or inbound raw transaction-sign endpoint. The
public gateway has neither the Provider key nor the policy database. The
authorizer validates the descriptor, full previous transaction, PSBT, Arkade
packet, WebAuthn assertion, DirectP256 signature, hot signature, fee limits,
and period allowance before durably reserving budget and using its private
Provider key. It persists that exact partial PSBT before sending it to the
code-pinned public Arkade Emulator; its response may add only the one expected
tweaked-Arkade signature.

## Vault and key model

These are ordinary Bitcoin Taproot UTXOs, not Ark VTXOs.

| Vault | Leaves | Cosigner keys |
| --- | --- | --- |
| Operational | hot + tweaked private Provider + tweaked public Arkade; hot + backup; CSV + backup | collaborative leaf only |
| Savings | hot + backup; longer CSV + backup | neither base nor tweaked cosigner identity appears |

Collaborative authorization script:

```text
<canonical transaction-local policy> OP_0 OP_SIGHASH
<0x11||directP256> OP_CHECKSIGFROMSTACK
```

The WebAuthn credential key is used only for off-chain origin/RP/UV checks.
`directP256` is a distinct PRF-derived P-256 key and signs the current Arkade
sighash. The on-chain packet contains its compact low-S signature, not the
WebAuthn assertion. A random secp256k1 hot key is encrypted under a
PRF-derived key. The hot, Provider, public Arkade, and backup identities are
pairwise independent under Taproot's x-only key semantics.

## Local regtest demonstration

Pin Go `1.26.6`. Docker, Docker Compose, Nigiri, curl, Chrome, and Bun are
needed for the complete browser proof.

```bash
# Private Emulator + provider UI. Open only http://localhost:8787.
make vault-demo
make vault-demo-down

go test ./poc/2fa-vault/...

# Chrome virtual-authenticator PRF primitive.
make vault-browser-fixture

# Full browser ceremony with an explicitly unsafe in-process test signer.
make vault-browser-e2e

# Opt-in Chrome -> RemoteSigner -> confirmed regtest transaction proof.
VAULT_LIVE_ACCEPTANCE=1 make vault-regtest-e2e
```

The live acceptance path creates/unlocks the disposable arkd regtest wallet,
funds the Operational output, completes the passkey/DirectP256/hot/private-
Provider/public-Arkade flow, publishes, mines, restarts the provider, and
verifies the same txid and durable policy state. It refuses to alter shared
Nigiri data.

The regtest launcher reads raw node JSON with
`docker exec bitcoin bitcoin-cli getnetworkinfo`, requires numeric Core
version `>= 300000`, and runs `testmempoolaccept` as the authoritative local
relay-policy gate before broadcast.

## Mutinynet demonstration

Use [the Mutinynet runbook](poc/2fa-vault/deploy/mutinynet/README.md). It
requires:

- a stable HTTPS domain and WebAuthn RP ID;
- a real compressed backup public key independent of every other role;
- a file-backed random provider scalar and one-time enrollment token stored
  outside this repository;
- explicit Operational and Savings CSV block delays; and
- the checkpoint-pinned Mutinynet Esplora backend.

The public Arkade cosigner origin, compressed base key, and exact accepted
version are build-time release pins. Its current `GetInfo` omits a network
field, so it is not treated as network attestation; Esplora block-height 1
pins Mutinynet independently. A funded descriptor from the earlier two-key
template or v1 database is not auto-migrated.

The first-enrollment overlay mounts the token only until the exact vault tuple
is registered. Normal restarts use the base Compose file without that secret.
Funding comes from an external Mutinynet faucet or wallet; demo fund/mine
routes are regtest-only.

## Layout

```text
poc/2fa-vault/cmd/authorizer/       protected Mutinynet key+policy process
poc/2fa-vault/internal/authorizer/  strict key/secret/runtime assembly
poc/2fa-vault/internal/provider/    policy, PSBT checks, HTTP operations
poc/2fa-vault/internal/vault/       Taproot trees and Arkade script
poc/2fa-vault/web/                  current passkey POC client
poc/2fa-vault/deploy/mutinynet/     TLS gateway and deployment runbook
poc/2fa-vault/docs/                 wallet integration requirements
```

## Security claims and limits

| Claim | Current status |
| --- | --- |
| A network caller can bypass private policy through a generic signer on Mutinynet | **Closed by topology and code surface.** The key-owning authorizer exposes only constrained operations; dependency/binary tests reject generic Emulator/gRPC clients and demo signing code. The sole outbound signer call targets the release-pinned HTTPS Arkade endpoint, whose response is reduced to one exact verified signature delta. |
| Provider-key use is bound to WebAuthn, transaction, and budget checks | **Yes inside the Mutinynet software authorizer.** Key and authoritative ledger share one process; budget is reserved before key use. |
| Compromise of the host/root cannot extract or misuse the provider key | **No.** Docker hardening is process isolation, not an HSM/enclave boundary. |
| Compromised same-origin frontend is tolerated | **No.** Modified first-party JavaScript can steal the unlocked hot material or PRF result. The independent-wallet architecture is the next milestone. |
| Browser independently derives and reconciles the Arkade sighash | **Yes for the supported one-input POC template.** Go/JavaScript parity vectors pin the witness-masked digest. |
| Browser independently derives the complete versioned descriptor | **Not yet.** See the wallet Vault-mode requirements document. |
| Backup-key generation/storage/signing is implemented | **No.** Mutinynet requires a real public key, but its ceremony remains out of scope. |
| Both remote signatures and the completed ledger row are crash-atomic | **Staged, not atomic.** `reserved -> provider_signed -> completed` persists the exact request and private stage. An exact in-page retry resumes the public stage; a changed request is rejected and ambiguous reservations are never released. |
| Mainnet readiness | **No.** Mutinynet only; one isolated vault per authorizer instance. |

## Tests

```bash
go test ./poc/2fa-vault/...
bun test poc/2fa-vault/web/*.test.js
```

The suite covers every major module: tree/key separation, WebAuthn and P-256
validation, transaction-bound DirectP256, exact PSBT correspondence, all
three Taproot signatures, executable transaction/fee policy for both
cosigners, durable staged reservations,
enrollment/restart compatibility, explicit HTTP allowlists, Mutinynet chain
checkpointing, secret parsing, Compose isolation, and a built-authorizer
dependency/string scan.

Vault code is under `poc/2fa-vault/`; the rest is the pinned Emulator
snapshot. See [EMULATOR.md](EMULATOR.md), [SECURITY.md](SECURITY.md), and
[the detailed package notes](poc/2fa-vault/README.md).
