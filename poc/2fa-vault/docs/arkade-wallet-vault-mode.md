# Arkade Wallet Vault mode — frontend requirements

Status: architecture target, not implemented in this slice.

The audited UI starting point is
`arkade-os/wallet@ad691cf071080daf37607356ee47b7e4cc8ce34f`. Freeze that
revision for the first UI milestone; moving upstream branches are
informational until a deliberate dependency review. The VTXO-oriented ts-sdk
is not a dependency or integration target for this UTXO vault.

Product assumption: “second user key” means the independent owner/recovery
cosigner described below. If the product instead means a second everyday
co-approver, that requires a different Taproot tree and authorization policy
and must be decided before freezing descriptor v1.

The next client should be a dedicated **Vault mode** in an Arkade Wallet fork.
It must not reuse the wallet's current feature named “passkey”: that flow uses
WebAuthn `userHandle` as an encryption-secret carrier and does not provide the
PRF-derived, transaction-bound model required here. Vault mode needs its own
state machine, signer, descriptor, and API client.

The first release remains an on-chain Mutinynet Taproot vault (`tb1p...`). It
is not an Ark VTXO (`tark...`). Arkade Wallet's current wallet state, balance,
receive, send, and activity pipeline is VTXO-only, so Vault mode cannot be
implemented by injecting a new signer into that pipeline. It needs a parallel
L1 UTXO domain with its own discovery, full-prevout retrieval, coin selection,
fee estimation, publication, confirmation, and recovery state. The fork may
reuse the application shell and navigation, but it must keep `tb1...` UTXOs
and `tark...` VTXOs visibly and technically separate. A future VTXO design
must separately account for the arkd server key and unilateral-exit rules
rather than relabeling this tree.

## Product boundary

Add a `VaultProvider` beside the existing wallet provider, with narrowly
scoped modules:

- `vault-core`: pure descriptor/tree derivation, Arkade sighash calculation,
  PSBT/prevout validation, policy normalization, and parity vectors;
- `vault-passkey`: foreground-only WebAuthn registration, assertion, and PRF;
- `vault-keystore`: IndexedDB encrypted hot-key envelope and crash-safe
  enrollment state;
- `vault-api`: constrained authorizer client, never a generic signing client;
- `vault-recovery`: independent backup descriptor pairing and recovery PSBTs;
  and
- Vault enrollment, dashboard, receive, send, activity, and recovery screens.

`VaultProvider` owns an L1-only balance and transaction history. Existing
VTXO coin selection, Ark receive addresses, batch/round state, service-worker
wallet persistence, send APIs, and activity reducers are not valid sources of
truth for the vault. Cross-mode transfers are explicit Bitcoin transactions:
the UI must never merge the two balances or imply that a `tb1...` vault output
is immediately spendable through the VTXO send flow.

## Standalone vault client boundary

Keep the first client deliberately small and orthogonal to ts-sdk. A local
`vault-client` feature directory owns only the public descriptor, confirmed L1
UTXOs and full previous transactions, PSBT construction/review, WebAuthn/PRF
ceremony, encrypted hot key, constrained authorizer calls, publication, and
confirmation polling. It may reuse general-purpose audited Bitcoin encoding
libraries, but it must not import VTXO wallet state or expose a generic signing
API.

The useful internal boundary is four operations: rebuild and verify a public
descriptor; discover confirmed descriptor-matching UTXOs; review and authorize
one constrained spend; and publish/status by the completed issuance challenge.
Do not generalize this into a reusable SDK until the Mutinynet flow and recovery
path are proven. If it later becomes a package, it remains a UTXO vault/cosigner
package rather than an extension of the Ark VTXO SDK.

No PRF result, DirectP256 scalar, hot scalar, plaintext seed, or decrypted key
may enter React context, logs, telemetry, `localStorage`, or a service worker.
The existing service-worker wallet serializes signing identities and is not a
suitable place for this interactive vault signer. Keep secrets in a
foreground-only operation scope and wipe them after signing.

## Key roles

These roles are cryptographically distinct and must never be collapsed:

| Role | Curve/location | Use |
| --- | --- | --- |
| WebAuthn credential | P-256 authenticator | Off-chain origin/RP/UP/UV assertion only |
| PRF result | 32-byte ephemeral browser secret | Domain-separated derivation root; never transmitted |
| DirectP256 | PRF-derived P-256 | Signs the exact Arkade transaction digest committed in the packet |
| Hot | random secp256k1, PRF-encrypted | BIP342 Operational/owner signature |
| Private Provider base | secp256k1 inside authorizer | Tweaked collaborative signature after WebAuthn, durable allowance reservation, and policy approval |
| Public Arkade base | release-pinned secp256k1 at the hosted Emulator | Independently tweaked third collaborative signature after executing the same committed transaction-local policy |
| Backup/recovery | secp256k1 child in independent wallet | Owner and CSV recovery paths; never held by provider |

The passkey does not sign Bitcoin. One ceremony verifies WebAuthn semantics
off-chain and supplies PRF output locally; DirectP256 and hot keys perform the
transaction signatures.

Replacing a passkey changes DirectP256. Treat replacement as a guided vault
migration/recovery transaction, not a metadata update.

## Required user flows

Enrollment state machine:

```text
capability check
  -> pair independent recovery signer
  -> choose policy
  -> create passkey
  -> stage encrypted local record
  -> commit enrollment
  -> independently rebuild/compare descriptor
  -> ready
```

Enrollment screens must:

1. Require HTTPS, the exact final RP ID/origin, ES256, user verification,
   discoverable credentials, a 32-byte PRF result, and IndexedDB.
2. Offer explicit roles: create a vault, pair as recovery signer, or import a
   watch-only vault.
3. Import a public recovery descriptor, materialize a fresh child, show its
   fingerprint/index, and require proof of possession before funding. The
   recovery wallet signs a domain-separated enrollment/descriptor hash with
   that exact child; the client verifies a BIP340 Schnorr proof against the
   materialized public key. An equivalent wallet-signed challenge is acceptable
   only if its domain and encoding are frozen in descriptor v1.
4. Show transaction cap, period allowance, absolute/feerate caps, and both CSV
   delays with block counts and approximate-time labels.
5. Obtain a server registration challenge. The server must parse and verify
   the authenticator registration result; it must not trust a client-supplied
   WebAuthn public key.
6. Display provider and recovery fingerprints, descriptor hash, Operational
   and Savings addresses, provider exclusion from Savings, and the exact
   policy before funding.

Normal operation:

```text
locked -> local passkey login -> ready -> compose -> local review
       -> transaction-bound passkey ceremony -> direct+hot signed
       -> private Provider signed -> public Arkade signed
       -> local exact two-signature-delta verification
       -> publish -> confirmed
```

Login and payment approval are separate events. Login uses a local/random
challenge only to unlock the UI. Every payment uses a transaction-bound
assertion whose challenge is the independently calculated Arkade transaction
digest. An exact retry may replay it only for the identical staged request.

Mutinynet send UX must accept a Bitcoin address, discover confirmed UTXOs and
full previous transactions through a pinned backend, select inputs, estimate
fees, and display recipient, input, change, packet, fee, fee rate, policy
impact, and remaining allowance before ceremony. The first release may retain
the one-input/one-recipient restriction, but it must make that limit explicit.

## Recovery signer descriptor

The second user or backup wallet exports a public HD descriptor from a
dedicated recovery account, for example:

```text
tr([d34db33f/86'/1'/7']tpub.../0/*)
```

Account index `7'` is only an allocated example. The fork must reserve and
document a numeric vault-recovery account index.

The vault persists:

- the exact account descriptor;
- selected child index;
- materialized descriptor;
- 33-byte compressed child public key; and
- human-verifiable master fingerprint.

Use a dedicated account so recovery keys cannot collide with ordinary receive
rotation. Mutinynet descriptors use testnet extended-key encoding, so the
custom network identity must remain an explicit descriptor field.

The recovery wallet must be able to import the resulting public vault
descriptor, watch both addresses, review/sign the owner path with the hot
signer, sign the matured CSV recovery path independently of the provider, and
transfer PSBTs by QR/file/deep link. Show exact eligible block height, not only
an estimated date.

## `VaultPublicDescriptor v1`

Freeze a versioned public object before UI work. It should contain at least:

```json
{
  "schema": "arkade-vault/v1",
  "network": "mutinynet",
  "vaultId": "<random 32-byte id>",
  "template": "direct-p256-3of3-v2",
  "keys": {
    "hot": "<compressed secp256k1>",
    "recovery": {
      "materializedDescriptor": "<descriptor>",
      "compressedPub": "<compressed secp256k1>",
      "fingerprint": "<8 hex chars>",
      "index": 0
    },
    "providerBase": "<compressed private Provider secp256k1>",
    "tweakedProvider": "<derived compressed secp256k1>",
    "arkadeBase": "<compressed release-pinned public Arkade secp256k1>",
    "tweakedArkade": "<derived compressed secp256k1>",
    "arkadeOrigin": "https://emulator.mutinynet.arkade.sh",
    "arkadeVersion": "<exact reviewed GetInfo version>",
    "directP256": "<compressed P-256>"
  },
  "policy": {
    "operationalCsvBlocks": 0,
    "savingsCsvBlocks": 0,
    "txCapSats": 0,
    "periodAllowanceSats": 0,
    "absoluteFeeCapSats": 0,
    "feerateCapSatVb": 0,
    "period": "utc-day"
  },
  "operational": {
    "tapTree": "<canonical bytes>",
    "scriptPubKey": "<hex>",
    "address": "tb1p..."
  },
  "savings": {
    "tapTree": "<canonical bytes>",
    "scriptPubKey": "<hex>",
    "address": "tb1p..."
  },
  "descriptorHash": "<sha256 of canonical encoding>"
}
```

Credential ID, WebAuthn public key, origin/RP ID, encrypted hot ciphertext,
bootstrap token, and private material are not part of the public descriptor.

Given this object, both Go and TypeScript must independently rebuild and
compare:

- DirectP256 authorization script and both signer tweaks over the same
  `ArkadeScriptHash`;
- Operational collaborative, owner, and recovery leaves;
- Savings owner/recovery leaves and exclusion of both cosigner identities;
- tree ordering, control blocks, scriptPubKeys, and addresses; and
- policy/network/template identity and descriptor hash.

Freeze one canonical byte encoding and publish Go/TypeScript golden vectors.
The first implementation milestone is byte-for-byte parity for every derived
leaf, tree, script, address, tweaked key, and descriptor hash. No client may
accept an authorizer-supplied address without deriving it locally.

## Local PSBT and challenge verification

Before any passkey or hot-key use, Vault mode must:

1. fetch and parse the complete previous transaction;
2. match outpoint, vout, WitnessUtxo value/script, and descriptor-derived
   Operational output;
3. reconstruct the exact collaborative leaf/control block;
4. require a native-SegWit recipient and validate change, the exact canonical
   Ark extension as the final zero-valued output, amounts, absolute fee, and fee
   rate;
5. calculate the BIP342 hot sighash and Arkade `OP_SIGHASH` digest locally;
6. use that digest as the transaction-bound WebAuthn challenge and DirectP256 message;
7. insert DirectP256 and hot signatures locally; and
8. after authorization, require byte-for-byte PSBT preservation except for
   exactly two new valid signatures: the expected tweaked private Provider and
   tweaked public Arkade keys, yielding the exact three-key collaborative set.

The authorizer independently repeats the same checks. Transaction-local shape,
native-SegWit recipient, change, exact final packet script/position,
absolute-fee, and exact final-witness feerate rules are committed in the shared
AuthorizationScript and therefore execute under
both independent tweaked signers. The cumulative daily allowance remains
stateful and is enforced only by the private authorizer before its key use.
Security must no longer depend on trusting `/draft`, `/preflight`, or `/bind`
output.

## Target API

Migrate from the singleton POC API toward this narrow contract:

- `GET /v1/config`: network, exact origin/RP ID, both cosigner base/tweaked
  keys, release-pinned Arkade origin/version, template version/hash, policy
  bounds, and endpoint identity;
- `POST /v1/enrollment/options`: authorized enrollment ID, random challenge,
  expiry;
- `POST /v1/enrollment/commit`: authenticator registration result, hot and
  DirectP256 public keys, materialized recovery descriptor, selected policy,
  and client descriptor hash; returns the complete normalized descriptor;
- `GET /v1/vaults/{id}/descriptor`;
- `GET /v1/vaults/{id}/status`;
- `POST /v1/vaults/{id}/authorize`: exact locally reviewed PSBT plus its
  transaction-bound assertion, already carrying DirectP256 and hot
  signatures; the server durably stages the exact request, private signature,
  then public signature;
- `POST /v1/vaults/{id}/issuances/{challenge}/publish`: issuance identifier
  only, never an arbitrary raw transaction; and
- `GET /v1/vaults/{id}/issuances/{challenge}`.

A first beta may run one vault per isolated authorizer. A shared public service
requires random vault IDs plus per-vault credentials, descriptors, policies,
and ledgers; CORS/origin and authorization must be explicit per operation.

## Storage and deployment

Store an opaque AES-GCM envelope in IndexedDB containing the hot scalar. Bind
its AAD to the vault ID, credential ID, hot and DirectP256 public keys,
descriptor hash, origin, and schema version. Persist versioned PRF salt/HKDF
labels and a random nonce, and verify the derived hot public key after every
decrypt. Support encrypted export or independent backup; recovery must not
depend on the authorizer's copy.

The long-term topology should separate a reproducible client origin from the
API origin:

```text
https://wallet.example    static/signed Vault-mode client and WebAuthn RP
https://vault-api.example constrained authorizer API; never serves JavaScript
```

Use exact-origin CORS, pinned provider/template identity, no analytics or
remote scripts on vault routes, and no service-worker update during an active
ceremony. Choose the final RP domain before any vault is funded.

## Delivery phases

1. Freeze `VaultPublicDescriptor v1` and Go/TypeScript parity vectors.
2. Fork the current Arkade Wallet release and scaffold a parallel L1 UTXO
   domain plus dedicated Vault mode; do not route it through the VTXO store.
3. Implement pure TypeScript tree, UTXO/prevout, PSBT, and Arkade-digest
   checks.
4. Add secure registration and configurable per-vault policy APIs.
5. Build enrollment, dashboard, receive, send, and activity UX.
6. Add second-wallet pairing plus owner and CSV recovery flows.
7. Demonstrate Mutinynet faucet -> fund -> passkey-authorized spend ->
   confirmation -> recovery.
8. Keep Ark VTXO integration out of scope unless a separate product design
   explicitly requires it.

Pinned review sources and moving upstream starting points:

- [Pinned Arkade Wallet tree](https://github.com/arkade-os/wallet/tree/ad691cf071080daf37607356ee47b7e4cc8ce34f)
- [Moving Arkade Wallet repository](https://github.com/arkade-os/wallet)
- [Current wallet biometrics/passkey implementation](https://github.com/arkade-os/wallet/blob/ad691cf071080daf37607356ee47b7e4cc8ce34f/src/lib/biometrics.ts)
