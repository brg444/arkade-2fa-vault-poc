# Arkade Wallet Vault mode — v3 frontend requirements

Status: architecture target, not implemented in this repository.

Freeze the first UI milestone to the audited candidate
`arkade-os/wallet@ad691cf071080daf37607356ee47b7e4cc8ce34f`. Treat
`arkade-os/ts-sdk@201368...` as a reference only until its full revision is
pinned and reviewed. Moving upstream branches are informational, not implicit
dependency updates.

Vault mode is an on-chain Mutinynet Taproot wallet (`tb1p...`), not an Ark
VTXO wallet (`tark...`). It needs a parallel L1 UTXO domain with its own
descriptor, discovery, full-prevout retrieval, coin selection, fee estimation,
publication, confirmation, admin, and recovery state. It may reuse the app
shell, but it must never merge L1 vault balances or send paths with VTXOs.

Do not reuse Arkade Wallet's current feature named “passkey.” That flow uses
WebAuthn `userHandle` as an encryption-secret carrier and does not implement
this transaction-bound WebAuthn + PRF model.

## Frozen role names and trust statement

All six names below are protocol vocabulary and API/schema identifiers:

| Role | Key/type | Authority |
| --- | --- | --- |
| `PhoneDirectP256` | P-256, PRF-derived | Signs the exact Arkade digest inside the packet and is independently verified by the authorization script |
| `PhoneRoutineBIP340` | random secp256k1 key encrypted by a PRF-derived KEK | Mandatory Bitcoin signature for Routine spends; software in foreground browser memory, not authenticator hardware or attestation |
| `ExternalOwnerWallet` | independent secp256k1 public key from an external wallet | Mandatory Admin/full-sweep/policy-migration signature; never used by Routine UI/API |
| `RecoveryKey` | independent secp256k1 public key from a recovery wallet | Co-signs Admin and alone signs each CSV recovery leaf |
| `VaultCosigner` | file-backed secp256k1 key in the policy-owning authorizer | Tweaked Routine signature after WebAuthn, static policy, and durable allowance reservation |
| `ArkadeCosigner` | release-pinned public Emulator secp256k1 key | Independently tweaked Routine signature after the same transaction-local script policy executes |

WebAuthn ES256 is a seventh public authentication identity, used only to
verify origin, RP ID, UP, UV, and the exact transaction-bound challenge. It is
not a Bitcoin signature and is not `PhoneDirectP256`.

The PoC's PhoneRoutine key is random browser-generated software material
encrypted under the passkey PRF. Product language must not call it a hardware,
Secure Enclave, authenticator-resident, or attested Bitcoin key.

All secp256k1 roles, including both tweaks, are pairwise independent by x-only
identity. RecoveryKey possession must be proven before funding with a
domain-separated Schnorr proof over the enrollment/descriptor hash (or an
equivalent external-wallet challenge) and the materialized child public key
must match exactly. ExternalOwnerWallet requires the same proof-of-possession
quality before funding.

## Exact v3 Taproot trees

Operational has exactly three leaves:

```text
Routine:
  3-of-3(
    PhoneRoutineBIP340,
    tweak(VaultCosigner, ArkadeScriptHash),
    tweak(ArkadeCosigner, ArkadeScriptHash)
  )

Admin / full sweep / policy migration:
  2-of-2(ExternalOwnerWallet, RecoveryKey)

Emergency recovery:
  CSV(operationalDelay) + RecoveryKey
```

Savings has exactly two leaves:

```text
Admin:
  2-of-2(ExternalOwnerWallet, RecoveryKey)

Emergency recovery:
  CSV(savingsDelay) + RecoveryKey
```

Savings must exclude PhoneRoutineBIP340 and both VaultCosigner/ArkadeCosigner
base and tweaked identities. Routine must not contain ExternalOwnerWallet or
RecoveryKey.

Every Routine spend must return non-dust change to the identical current
Operational script. There is no valid no-change Routine branch. Therefore
Routine APIs cannot full-sweep or replace policy while either cosigner remains
honest. A compromise of PhoneRoutineBIP340, PhoneDirectP256/WebAuthn, and both
cosigners can spend; no stronger invariant is claimed.

The authorization script independently pins version 2, locktime 0, one final
input, a native-SegWit recipient at output 0, mandatory same-script change at
output 1, the exact zero-valued Arkade packet at output 2, recipient/dust/fee
and exact final-witness fee-rate limits, then verifies PhoneDirectP256 over
`OP_SIGHASH`. The stateful UTC allowance remains in the authoritative SQLite
ledger, not the VM.

## `VaultPublicDescriptor v3`

Freeze Go/TypeScript parity vectors before UI work. A canonical illustrative
descriptor is:

```json
{
  "schema": "arkade-vault/v3",
  "network": "mutinynet",
  "vaultId": "operational-vault-v1",
  "templateVersion": "phone-direct-p256-routine-3of3-admin-2of2-v3",
  "policyVersion": "mandatory-change-tx50k-day100k-fee5k-feerate10-onchain-v3",
  "keys": {
    "phoneRoutineBip340": "<compressed secp256k1>",
    "phoneDirectP256": "<compressed P-256>",
    "externalOwnerWallet": "<compressed secp256k1>",
    "recoveryKey": "<compressed secp256k1>",
    "vaultCosignerBase": "<compressed secp256k1>",
    "tweakedVaultCosigner": "<compressed secp256k1>",
    "arkadeCosignerBase": "<compressed secp256k1>",
    "tweakedArkadeCosigner": "<compressed secp256k1>"
  },
  "arkadeCosigner": {
    "origin": "https://emulator.mutinynet.arkade.sh",
    "version": "v0.0.7-rc.1"
  },
  "csv": { "operationalBlocks": 288, "savingsBlocks": 4032 },
  "policy": {
    "recipientDustSats": 330,
    "recipientCapSats": 50000,
    "periodAllowanceSats": 100000,
    "absoluteFeeCapSats": 5000,
    "feerateCapSatVb": 10
  },
  "operational": { "script": "<hex>", "address": "tb1p..." },
  "savings": { "script": "<hex>", "address": "tb1p..." }
}
```

The descriptor hash uses a versioned canonical binary encoding, not generic
JSON stringification. Go and TypeScript must produce identical authorization
script bytes/hash, both tweaks, three Operational leaves, two Savings leaves,
Taproot roots/control blocks, scripts, addresses, Routine witness weight, and
descriptor hash.

Credential ID, WebAuthn public key, RP/origin, encrypted PhoneRoutine envelope,
bootstrap state, and issuance rows are private local/service state, not public
descriptor fields.

If recovery uses an HD descriptor, use valid numeric BIP32 paths, for example
`tr([d34db33f/86'/1'/7']tpub.../0/*)`. Account index 7 is illustrative; the
fork must reserve and document its actual numeric vault-recovery account.

## Client modules

Add a `VaultProvider` beside the existing wallet provider:

- `vault-core`: pure descriptor/tree derivation, PSBT/prevout checks, Arkade
  digest, fee/weight calculations, and Go/TypeScript vectors;
- `vault-passkey`: foreground-only WebAuthn registration/assertion and PRF;
- `vault-keystore`: encrypted PhoneRoutine envelope plus crash-safe enrollment;
- `vault-api`: exact constrained authorizer client, never generic signing;
- `vault-admin`: file/QR PSBT handoff to ExternalOwnerWallet and RecoveryKey;
- `vault-recovery`: watch-only recovery descriptor and CSV readiness; and
- dedicated enrollment, dashboard, receive, routine send, activity, admin,
  and recovery screens.

No PRF output, PhoneDirect scalar, PhoneRoutine scalar, external-wallet private
material, or plaintext seed may enter React context, logs, telemetry,
`localStorage`, session storage, or a service worker. Decrypt only within a
foreground operation and wipe best-effort after signing. ExternalOwnerWallet
and RecoveryKey private material never enter the app unless a separately
audited external-wallet transport explicitly provides a signature.

## Enrollment

1. Fetch deployment identity and verify network, origin/RP ID, v3
   template/policy, CSV values, VaultCosigner identity, and the code-pinned
   ArkadeCosigner release identity.
2. Perform WebAuthn registration with required UV and PRF support.
3. Derive PhoneDirectP256; generate PhoneRoutineBIP340; encrypt the latter
   under a PRF-derived AES-GCM KEK with descriptor-bound AAD.
4. Pair ExternalOwnerWallet and RecoveryKey independently and require proof of
   possession for both.
5. Derive the full v3 descriptor locally and compare every server-returned
   script/address/tweak/version field.
6. Stage encrypted local enrollment before commit; promote only after exact
   registration and status reconciliation. Pending recovery must perform fresh
   UV+PRF, decrypt, and key verification before any exact retry.
7. Display all six role fingerprints, descriptor hash, both addresses, CSV
   delays, policy values, and explicit Savings routine-signer exclusion before
   allowing funding.

Replacing any passkey, Phone key, ExternalOwnerWallet, RecoveryKey, cosigner,
CSV, template, policy, RP, or origin is a guided on-chain Admin migration, not
a metadata update. v1/v2 descriptors and funded outputs are never reinterpreted
as v3.

## Routine spend orchestration

Before any phone secret use, Vault mode must:

1. load and hash-check the v3 descriptor;
2. verify the complete previous transaction, outpoint, WitnessUtxo, current
   Operational script, and confirmed/unspent state;
3. reconstruct the exact Routine leaf/control block and mandatory recursive
   change;
4. validate exact recipient/change/packet ordering, values, caps, fee, and
   final 3-signature weight;
5. independently derive the Arkade digest and reconcile preflight exactly;
6. perform the transaction-bound WebAuthn assertion, PhoneDirectP256 packet
   signature, and PhoneRoutineBIP340 Taproot signature locally;
7. submit an exact Phone-signed PSBT; and
8. accept a response only if all non-signature bytes are identical, the
   PhoneRoutine signature is unchanged, and exactly two valid signatures were
   added under the pinned tweaked VaultCosigner and ArkadeCosigner keys, in
   either order.

The server state machine is exactly:

```text
reserved(request_psbt)
  -> vault_signed(request_psbt, vault_psbt)
  -> completed(request_psbt, vault_psbt, signed_psbt)
```

On a transient public-cosigner failure, preserve the byte-identical authorize
body only in page memory and retry it before generating any new assertion or
signature. Never persist assertion/PSBT retry material.

## Admin and recovery

ExternalOwnerWallet is admin-only and never appears in routine API requests.
Admin/full-sweep/policy-migration PSBTs are constructed locally or with the
file-only `cmd/adminpsbt` reference, transferred to both ExternalOwnerWallet
and RecoveryKey, and finalized only after exact 2-of-2 signature verification
and script execution. No HTTP signer route is allowed.

Recovery builds a CSV sequence from the descriptor, verifies maturity against
an independent chain source, uses only RecoveryKey, and explicitly displays
which Operational or Savings delay applies. A recovery PSBT must not silently
fall back to Routine or Admin.

## Narrow target API

Prefer resource-scoped equivalents of the current PoC surface:

- `GET /v1/config`: network, origin/RP, v3 template/policy, CSV values, both
  cosigner identities;
- enrollment options/commit with Phone public identities and the public
  ExternalOwnerWallet/RecoveryKey descriptor inputs;
- descriptor/status reads;
- draft/preflight/bind/authorize for Routine only;
- publish/status by completed issuance challenge only.

There is no generic sign endpoint, client-supplied raw publish endpoint,
ExternalOwnerWallet signer endpoint, Admin endpoint, or RecoveryKey signer
endpoint. Admin/recovery are external-wallet PSBT flows.

## Rollout

1. Freeze v3 canonical encoding and Go/TypeScript parity corpus.
2. Implement watch-only descriptor import and address/script comparison.
3. Implement WebAuthn/PRF plus encrypted PhoneRoutine lifecycle and crash
   recovery.
4. Implement exact Routine PSBT review, phone signing, two-signature response
   delta verification, publication, and same-page exact retry.
5. Implement independent L1 discovery/history and confirmation reconciliation.
6. Implement ExternalOwnerWallet+RecoveryKey admin handoff and CSV recovery.
7. Run Mutinynet enrollment -> fund -> routine spend -> restart -> admin sweep
   -> recovery rehearsal with adversarial parity tests before considering any
   production hardening.

This remains Mutinynet-only software isolation. Same-origin client compromise,
host/root compromise, public Arkade availability/privacy, and SQLite rollback
remain explicit limits.
