# Arkade 2FA Vault POC

Demonstrable **L1 Taproot 2FA cosigning vault** on Arkade. A passkey
ceremony authorizes a transaction, a separate PRF-derived P-256 key signs the
Arkade transaction digest, and PhoneRoutineBIP340 plus two independently tweaked
cosigners produce the exact three-signature Taproot spend.

This is a proof of concept for non-mainnet funds. The Mutinynet deployment is
a hardened software process, not an enclave, HSM, or production custody
system. Never fund it with real BTC.

## Two execution profiles

| Profile | Purpose | VaultCosigner boundary |
| --- | --- | --- |
| Regtest | Reproducible local browser, two independent Emulators, mining, and restart demo | `cmd/provider` calls disposable VaultCosigner and ArkadeCosigner fixtures; ExternalOwnerWallet and RecoveryKey are public deterministic fixtures |
| Mutinynet | Internet-deployable POC | `cmd/authorizer` alone owns the private VaultCosigner key and SQLite ledger; it then calls one release-pinned public ArkadeCosigner through narrow outbound HTTPS |

The Mutinynet topology contains no generic/gRPC signer client, generic signing
RPC, demo funding/mining route, or inbound raw transaction-sign endpoint. The
public gateway has neither the VaultCosigner key nor the policy database. The
authorizer validates the descriptor, full previous transaction, PSBT, Arkade
packet, WebAuthn assertion, PhoneDirectP256 signature, PhoneRoutineBIP340
signature, mandatory recursive change, fee limits,
and period allowance before durably reserving budget and using its private
VaultCosigner key. It persists that exact partial PSBT before sending it to the
code-pinned public Arkade Emulator; its response may add only the one expected
tweaked-ArkadeCosigner signature.

## Vault and key model

These are ordinary Bitcoin Taproot UTXOs, not Ark VTXOs.

| Vault | Leaves | Cosigner keys |
| --- | --- | --- |
| Operational | Routine 3-of-3 PhoneRoutineBIP340 + tweaked VaultCosigner + tweaked ArkadeCosigner; Admin 2-of-2 ExternalOwnerWallet + RecoveryKey; CSV + RecoveryKey | Routine leaf only |
| Savings | ExternalOwnerWallet + RecoveryKey; longer CSV + RecoveryKey | neither base nor tweaked routine cosigner identity appears |

Collaborative authorization script:

```text
<canonical transaction-local policy> OP_0 OP_SIGHASH
<0x11||directP256> OP_CHECKSIGFROMSTACK
```

The WebAuthn credential key is used only for off-chain origin/RP/UV checks.
`directP256` is the distinct PRF-derived PhoneDirectP256 key and signs the current Arkade
sighash. The on-chain packet contains its compact low-S signature, not the
WebAuthn assertion. A random secp256k1 PhoneRoutineBIP340 software key is
encrypted under a PRF-derived key. PhoneRoutineBIP340, ExternalOwnerWallet,
RecoveryKey, VaultCosigner, ArkadeCosigner, and both routine tweaks are
pairwise independent under Taproot's x-only key semantics.

Routine spends must return a non-dust output to the identical Operational
script. Full sweep or policy migration instead uses the file-only Admin handoff
and requires exact ExternalOwnerWallet + RecoveryKey signatures; neither
private key is present in the browser, gateway, or authorizer.

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
funds the Operational output, completes the passkey/PhoneDirectP256/
PhoneRoutineBIP340/VaultCosigner/ArkadeCosigner flow, publishes, mines,
restarts the provider, and
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
- real independent compressed ExternalOwnerWallet and RecoveryKey public keys;
- a file-backed random VaultCosigner scalar and one-time enrollment token stored
  outside this repository;
- explicit Operational and Savings CSV block delays; and
- the checkpoint-pinned Mutinynet Esplora backend.

The public Arkade cosigner origin, compressed base key, and exact accepted
version are build-time release pins. Its current `GetInfo` omits a network
field, so it is not treated as network attestation; Esplora block-height 1
pins Mutinynet independently. Funded legacy descriptors and v1/v2 databases
are not auto-migrated or reinterpreted as v3.

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
| VaultCosigner-key use is bound to WebAuthn, transaction, and budget checks | **Yes inside the Mutinynet software authorizer.** Key and authoritative ledger share one process; budget is reserved before key use. |
| Compromise of the host/root cannot extract or misuse the VaultCosigner key | **No.** Docker hardening is process isolation, not an HSM/enclave boundary. |
| Compromised same-origin frontend is tolerated | **No.** Modified first-party JavaScript can steal the unlocked PhoneRoutineBIP340 material or PRF result. The independent-wallet architecture is the next milestone. |
| Browser independently derives and reconciles the Arkade sighash | **Yes for the supported one-input POC template.** Go/JavaScript parity vectors pin the witness-masked digest. |
| Browser independently derives the complete versioned descriptor | **Not yet.** See the wallet Vault-mode requirements document. |
| ExternalOwnerWallet/RecoveryKey generation, storage, and signing ceremonies are implemented | **No.** Mutinynet requires real independent public keys; the file-only admin handoff verifies their signed PSBT but does not hold either secret. |
| Both cosigner stages and the completed ledger row are crash-atomic | **Staged, not atomic.** `reserved -> vault_signed -> completed` persists the exact request and private stage. An exact in-page retry resumes the public stage; a changed request is rejected and ambiguous reservations are never released. |
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
