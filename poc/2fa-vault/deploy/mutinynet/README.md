# Mutinynet deployment runbook

**Live enroll is v5** (`phone-hww-recovery-staged-v5`). Recovery is
optional. Leftover v4 rows still load. This runbook stands up the
validating cosigner, not the PWA. See wallet `docs/v5-overview.md`.

This brings up the demonstrable Mutinynet POC as:

```text
browser -> public Caddy TLS/static gateway -> internal authorizer
                                             |-> pinned HTTPS public Arkade Emulator
                                             `-> checkpoint-pinned HTTPS Esplora
```

The authorizer is the only process with the VaultCosigner key and authoritative
SQLite ledger. Compose runs no local Emulator, generic inbound signer, demo
wallet, funding route, or mining route. The authorizer does make one narrow
outbound HTTPS call to the release-pinned public Arkade Emulator for the third
routine signature; `/v1/onchain-tx` is never exposed through the gateway.

The only live Mutinynet authorizer is Railway `authorizer-next`. The
older Railway `authorizer` service and Fly `arkade-vault-demo-api` app
are retired.

The live enroll tree is `phone-hww-recovery-staged-v5`. Routine Operational
is exact 3-of-3: browser-memory `PhoneRoutineBIP340`, tweaked private
`VaultCosigner`, and tweaked public `ArkadeCosigner`. Phone approval also
requires the separate WebAuthn and `PhoneDirectP256` authorization.
Admin/full sweep is 2-of-2 device + hardware
(`PhoneRoutineBIP340 + ExternalOwnerWallet`). There is no singlesig CSV
on Normal. Skip recovery and the family is two guardians. Add recovery
and it is a third. `/v1/register` is not on this deployment; enrollment
is invite-gated `/v1/enroll/*`. Do not mint v4.

Issuance is staged as:

```text
reserved(request_psbt)
  → vault_signed(request_psbt, vault_psbt)
  → completed(request_psbt, vault_psbt, signed_psbt)
```

The exact request and allowance are durable before private key use; the private
result is durable before public dispatch. Every stage counts against allowance,
an exact retry resumes without repeating a stored signer, and ambiguous
failures are never released.

This is non-mainnet test software. Use Mutinynet coins only. Docker isolation
does not provide an HSM or enclave security boundary.

## Prerequisites

- Docker Engine and Docker Compose `2.33.1` or newer (`gw_priority` is used).
- A lowercase DNS name pointing at the host, with inbound TCP 80 and 443.
- A stable HTTPS origin. Changing the domain changes the WebAuthn RP and
  requires migration into a newly enrolled vault.
- Availability of the release-pinned public Arkade Emulator. Its origin,
  compressed base key, and exact allowed version are code constants, not
  operator environment inputs.
- `openssl`, `curl`, and optionally `jq` for the walkthrough.
- Optionally `mutinynet-cli` with `mutinynet-cli login`; the hosted
  [Mutinynet faucet](https://faucet.mutinynet.com/) is the no-install path.
- An ExternalOwnerWallet hardware key capable of exporting a real compressed
  secp256k1 public key and signing a Taproot script-path PSBT. That ceremony
  is outside this repository. Do not use the public G or 2G fixtures.

Run every Compose command below from the repository root.

This v4 release does not reinterpret leftover v3 SQLite rows as spendable
trees. Multi-tenant boot quarantines the exact leftover template
`phone-direct-p256-routine-3of3-admin-2of2-v3` and fails closed on any other
stored mismatch. Schema 6, if it ever drops `recovery_key_compressed`, is a
separate RFC. Do not test migration by overwriting the only custody state.

## 1. Prepare secrets outside the repository

Choose a directory that is not inside any Git checkout or Docker build
context. Restrict it to the operator account.

```bash
install -d -m 700 /absolute/operator/path/vault-secrets
umask 077
openssl rand -hex 32 > /absolute/operator/path/vault-secrets/vault-cosigner-key
openssl rand -hex 32 > /absolute/operator/path/vault-secrets/enrollment-token
chmod 0600 /absolute/operator/path/vault-secrets/vault-cosigner-key
chmod 0600 /absolute/operator/path/vault-secrets/enrollment-token
```

The `0700` parent directory prevents other host users from traversing to the
files. Host secret files stay owner-only mode `0600`. Compose `file:` secrets
are remounted inside the container for UID 10001 (engines typically present
them as `0444` in that mount namespace); do not chmod the host files world-
readable to compensate, and do not make the authorizer root. Compose
`uid/gid/mode` fields are not a portable fix for `file:` sources because
engines may ignore them. The VaultCosigner key remains mounted only into the
authorizer.

The VaultCosigner-key file must contain exactly one valid 32-byte secp256k1 scalar
as 64 hex characters, with an optional final LF. Startup rejects zero,
out-of-range scalars, scalar 1, and scalar N-1. If the random value is rejected,
replace it with a newly generated value.

The enrollment token is a one-time 32–256 byte value. It is entered in the
browser for the first registration and is never logged or stored by the
browser. Do not put either file in this repository or in a shell history as
literal secret text.

Export a real 33-byte compressed ExternalOwnerWallet (hardware) public key.
It must be independent of PhoneRoutineBIP340 and both cosigners. It must not
be either known public fixture (G or 2G) or its negation. Only that public
key enters Compose; the hardware private material stays on the device.

## 2. Set deployment inputs

The example CSV delays below are the live Mutinynet demo clocks, not a
general custody recommendation. Mutinynet targets roughly 30-second blocks,
so 144 blocks is about 72 minutes and 6 blocks about 3 minutes.
Reorganizations and block-time variance make wall-clock estimates
non-binding. Values must be in `1..65535`, and the device-only delay must
exceed the hardware-only delay.

Replace `YOUR_REAL_DOMAIN` and `YOUR_REAL_EMAIL` below before running the
commands. The domain must be under DNS you control and resolve publicly to
this host; reserved `.test`/`.example` names cannot complete public ACME.

```bash
export YOUR_REAL_DOMAIN='YOUR_REAL_PUBLIC_DOMAIN'
export YOUR_REAL_EMAIL='YOUR_REAL_OPERATOR_EMAIL'
export VAULT_DOMAIN="vault.${YOUR_REAL_DOMAIN}"
export ACME_EMAIL="${YOUR_REAL_EMAIL}"
export VAULT_VAULT_COSIGNER_KEY_FILE=/absolute/operator/path/vault-secrets/vault-cosigner-key
export VAULT_ENROLLMENT_TOKEN_FILE=/absolute/operator/path/vault-secrets/enrollment-token
export VAULT_EXTERNAL_OWNER_WALLET_PUB=02_REPLACE_WITH_REAL_66_HEX_EXTERNAL_OWNER_PUB
export VAULT_OPERATIONAL_CSV_BLOCKS=144
export VAULT_SAVINGS_CSV_BLOCKS=6
export VAULT_ESPLORA_URL=https://mempool.mutinynet.arkade.sh/api
```

`VAULT_DOMAIN` must be canonical lowercase ASCII without a trailing dot,
trailing slash, explicit `:443`, or path. The RP ID is exactly this hostname.

The public Arkade Emulator identity is not configured by this environment
block. This release pins all three values in `internal/deployment/config.go`:

- origin: `https://emulator.mutinynet.arkade.sh`;
- compressed base key:
  `03f823b9b2febc81f4af967e77aed2f541cbd3397c6d8f5a72e32eb7b471af889a`;
- exact version: `v0.0.7-rc.1`.

Compose intentionally exposes no override for them. The signer's `/v1/info`
response reports version and current/deprecated keys, but no network identity,
so it is not Mutinynet attestation. The authorizer establishes chain identity
separately by requiring Esplora height 1 to equal
`000002855893a0a9b24eaffc5efc770558a326fee4fc10c9da22fc19cd2954f9`.

Validate the resolved topology before starting it:

```bash
docker compose \
  -f poc/2fa-vault/docker-compose.mutinynet.yml \
  -f poc/2fa-vault/docker-compose.mutinynet.enroll.yml \
  config --quiet
```

## 3. Start the one-time enrollment topology

```bash
docker compose \
  -f poc/2fa-vault/docker-compose.mutinynet.yml \
  -f poc/2fa-vault/docker-compose.mutinynet.enroll.yml \
  up -d --build
```

Wait for TLS and the authorizer health check:

```bash
curl --fail --show-error https://$VAULT_DOMAIN/health
curl --fail --show-error https://$VAULT_DOMAIN/v1/status
```

Open the live wallet origin in a PRF-capable browser. Redeem an invite and
complete `/v1/enroll/start` → `/propose` → `/finish`. Verify status reports:

- `enrolled: true`;
- `network: "mutinynet"`;
- the exact HTTPS `clientOrigin` and RP ID;
- `externalOwnerWalletPub` exactly equal to
  `VAULT_EXTERNAL_OWNER_WALLET_PUB`;
- no `recoveryKeyPub` field;
- the independently derived `vaultCosignerBasePub` for the mounted scalar;
- `arkadeCosignerBasePub`, `arkadeCosignerOrigin`, and
  `arkadeCosignerVersion` exactly equal to the release pins above;
- distinct `phoneRoutineBip340Pub`, `tweakedVaultCosignerXOnly`, and
  `tweakedArkadeCosignerXOnly` identities;
- template `phone-direct-p256-routine-3of3-admin-phone-hww-v4`, policy
  `…onchain-v3`, and CSV 144/6;
- both `tb1p...` addresses and the configured economic caps; and
- `savingsExcludesRoutineCosigners: true`.

Enrollment is first-write locked. Record this public status before funding.

## 4. Remove the enrollment token from the running topology

After successful registration, recreate from the base file only:

```bash
docker compose \
  -f poc/2fa-vault/docker-compose.mutinynet.yml \
  up -d --force-recreate
```

Confirm the authorizer restarts and remains enrolled without the token file:

```bash
curl --fail --show-error https://$VAULT_DOMAIN/v1/status
```

Now destroy or securely archive the one-time token according to the
operator's secret-handling policy. Do not use the enrollment overlay again for
this database. If the database is empty and the token is absent, startup fails
closed as intended.

## 5. Fund and spend on Mutinynet

Copy `operationalAddress` from `/v1/status` and send Mutinynet sats to it from
an external wallet or the [hosted faucet](https://faucet.mutinynet.com/). With
the optional authenticated CLI, run:

```bash
mutinynet-cli login
mutinynet-cli onchain tb1p_REPLACE_WITH_OPERATIONAL_ADDRESS
```

Wait for confirmation. Record the funding txid, output index, and raw
transaction. With the configured Esplora endpoint:

```bash
curl --fail --show-error \
  "$VAULT_ESPLORA_URL/tx/REPLACE_WITH_FUNDING_TXID/hex"
curl --fail --show-error \
  "$VAULT_ESPLORA_URL/tx/REPLACE_WITH_FUNDING_TXID"
```

In the POC page enter:

- a native-SegWit recipient scriptPubKey in hex;
- an amount within the 50,000-sat transaction cap;
- a fee within both the 5,000-sat and 10-sat/vB limits;
- the complete funding transaction hex; and
- the Operational output index.

The current page has no friendly address-to-script field. As a temporary POC
workaround only, convert a Mutinynet `tb1...` recipient address with the
vendored, pinned client code in the page's browser console:

```javascript
const p = await import("/psbtcheck.js");
p.bytesToHex(p.scriptFromAddress("tb1_REPLACE_WITH_RECIPIENT", "mutinynet"));
```

Choose **Review**, verify the input, recipient, change, fee, and allowance,
then choose **Approve**. The page binds
PhoneDirectP256, decrypts and uses PhoneRoutineBIP340 locally, and submits the
phone-signed request. The authorizer first persists the VaultCosigner
signature, then asks the pinned public ArkadeCosigner for its signature. The
page accepts only its submitted PhoneRoutine signature
plus exactly those two new valid cosigner signatures, in either order, with no
duplicates, substitutions, or PSBT/transaction mutation. It then publishes
through Esplora and displays the txid/challenge. Track it with:

```bash
curl --fail --show-error \
  "https://$VAULT_DOMAIN/v1/tx?challenge=REPLACE_WITH_CHALLENGE_HEX"
```

The returned txid must equal the txid independently derived by the browser.

If `/v1/authorize` fails because the public signer or network is temporarily
unavailable, leave the reviewed fields and page unchanged and choose
**Approve** again. The page keeps the exact serialized authorize body
only in memory and resubmits those identical bytes; it does not generate a new
WebAuthn assertion, PhoneDirectP256 signature, or PhoneRoutine signature for the reserved
challenge. Reloading the page loses this retry material. A verified success or
any change of spend intent clears it. Assertion and PSBT material is never
written to `localStorage` or `sessionStorage`.

## 6. File-only admin/full-sweep handoff

Routine endpoints always require a non-dust recursive change output to the
same Operational script; they cannot perform a full drain or replace policy.
For an intentional sweep or migration, save the enrolled `/v1/status` JSON and
an operator-reviewed build request, then use the offline reference tool:

```bash
go run ./poc/2fa-vault/cmd/adminpsbt \
  -mode build -descriptor status.json -request admin-request.json \
  -out unsigned-admin.psbt

# Transfer the PSBT to the enrolled device + hardware and obtain both
# signatures without changing any PSBT field. The live wallet Savings
# spend/QR path is the supported product handoff.
go run ./poc/2fa-vault/cmd/adminpsbt \
  -mode finalize -descriptor status.json -psbt signed-admin.psbt \
  -out final-admin.psbt -tx-out final-admin.tx
```

The build request is JSON with `prevTxHex`, `vout`, `destinationScript`,
`destinationAmount`, and `fee`. The tool pins and reconstructs the exact v4
descriptor and Mutinynet Arkade release identity, verifies the full prevout,
rejects any `recoveryKeyPub`, requires device + hardware BIP340 signatures,
executes the finalized witness locally, opens no listener, and reads no
private key. Broadcast is an explicit operator step after reviewing
`final-admin.tx`.

## 7. Restart proof

Restart only the protected authorizer and verify that descriptor and policy
state survive:

```bash
docker compose \
  -f poc/2fa-vault/docker-compose.mutinynet.yml \
  restart vault-authorizer
curl --fail --show-error https://$VAULT_DOMAIN/v1/status
```

Changing the VaultCosigner key, ExternalOwnerWallet, network, CSV delays, client origin, RP
ID, template, or policy version must make restart fail rather than silently
derive a different vault. The credential/descriptor row carries a versioned
HMAC under a domain-separated key derived from the VaultCosigner scalar. A
VaultCosigner-key rotation therefore requires a reviewed migration with the old key
available; never edit the SQLite row or MAC in place.

Public Arkade Emulator rotation is deliberately separate. A fresh enrollment
accepts only the release-pinned base when it is the endpoint's current signer.
An existing HMAC-authenticated descriptor continues to require its exact
stored base/tweak: startup may accept that base only while the pinned endpoint
advertises it as an active deprecated signer under a reviewed, allowlisted
version. It never adopts a key advertised by `/v1/info`, and authorization
still requires the signature under the stored tweak. Removing that deprecated
key, changing the pinned origin, or using a non-allowlisted version makes
startup fail closed.

The current schema-5 credential and issuance schema is also exact. Pointing
this binary at a v1/v2 database fails with migration/restore guidance;
startup does not rewrite the old descriptor, ledger, or already funded
legacy UTXOs. The one leftover v3 template is quarantined by exact match.

## Stop without deleting custody state

```bash
docker compose \
  -f poc/2fa-vault/docker-compose.mutinynet.yml \
  down
```

Do not add `--volumes`: the named authorizer volume contains the authoritative
descriptor and issuance ledger. Take a file-level database/volume backup only
while the authorizer is stopped, or use SQLite's online backup API/tool; a
blind copy of a live SQLite file is not the documented procedure. Protect the
matching VaultCosigner-key backup under the operator's encrypted secret process.

There is no anti-rollback store. Restoring an older database snapshot can
restore an older allowance/reservation view while signatures and transactions
already exist. Reconcile every issuance against the chain and retained audit
records before bringing the key-owning authorizer back online after restore.

## Known limits

- The gateway serves the signing client from the API origin; compromised
  first-party JavaScript defeats factor separation.
- The public API has request-size and server/operation timeouts plus a bounded,
  non-queueing in-process admission limit for Draft, Preflight, Bind, and
  Authorize work. It has no distributed edge limiter or container CPU/memory
  quota. Put reviewed edge rate limits and host resource controls in front of
  any long-running public demonstration.
- The configured Esplora is checkpoint-pinned and response-bounded, but it is
  still trusted for availability and confirmation reporting; this POC is not
  an SPV client. Cross-check important funding and publication state with an
  independent Mutinynet source.
- The public Arkade Emulator is an availability and transaction-privacy
  dependency. Its signing response is treated as hostile and reconciled down
  to the one expected signature, but an outage can stop the routine
  path. Its `/v1/info` response has no network field; only the separate
  Esplora height-1 checkpoint pins Mutinynet.
- The browser independently derives and reconciles the restricted POC Arkade
  sighash, but does not yet derive a complete versioned vault descriptor.
- Friendly hardware pairing and transport UX is not implemented; the live
  wallet Savings QR handoff is the supported product path.
- This is invite-gated multi-tenant enrollment on the live authorizer, with
  code-pinned economic caps.
- Container/root compromise is outside the protected-key claim.
- Database snapshots have no anti-rollback protection.

The next client milestone is specified in
[../../docs/arkade-wallet-vault-mode.md](../../docs/arkade-wallet-vault-mode.md).
