# Mutinynet deployment runbook

This brings up the demonstrable Mutinynet POC as:

```text
browser -> public Caddy TLS/static gateway -> internal authorizer
                                             |-> pinned HTTPS public Arkade Emulator
                                             `-> checkpoint-pinned HTTPS Esplora
```

The authorizer is the only process with the provider key and authoritative
SQLite ledger. Compose runs no local Emulator, generic inbound signer, demo
wallet, funding route, or mining route. The authorizer does make one narrow
outbound HTTPS call to the release-pinned public Arkade Emulator for the third
collaborative signature; `/v1/onchain-tx` is never exposed through the gateway.

The collaborative Operational leaf is exact 3-of-3: browser hot key, tweaked
private Provider key, and tweaked public Arkade key. The two independent base
keys are tweaked with the same `ArkadeScriptHash`. The Savings tree excludes
both roles' base and tweaked identities.

Issuance is staged as:

```text
reserved(request_psbt)
  → provider_signed(request_psbt, provider_psbt)
  → completed(request_psbt, provider_psbt, signed_psbt)
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
- A separate backup wallet capable of producing a real compressed
  secp256k1 public key and later signing the owner/recovery paths. Its key
  ceremony is outside this repository.

Run every Compose command below from the repository root.

This v2 3-of-3 release does not auto-migrate an old v1 SQLite database or an
Operational UTXO funded to the former 2-of-2 tree. Preserve the old database
and keys and complete a reviewed old-tree spend/migration before enrolling and
funding a fresh v2 instance. Do not test migration by overwriting the only
custody state.

## 1. Prepare secrets outside the repository

Choose a directory that is not inside any Git checkout or Docker build
context. Restrict it to the operator account.

```bash
install -d -m 700 /absolute/operator/path/vault-secrets
openssl rand -hex 32 > /absolute/operator/path/vault-secrets/provider-key
openssl rand -hex 32 > /absolute/operator/path/vault-secrets/enrollment-token
chmod 0444 /absolute/operator/path/vault-secrets/provider-key
chmod 0444 /absolute/operator/path/vault-secrets/enrollment-token
```

The `0700` parent directory prevents other host users from traversing to the
files. The immutable files themselves use mode `0444` so the dedicated
container UID 10001 can read the file-backed Compose secret after it is bind
mounted. A normal owner-only mode 0600 file may be unreadable to that non-root
UID on Linux. Compose `uid/gid/mode` fields are not a portable fix for `file:`
sources because engines may ignore them. Do not make the authorizer root to
work around this. The provider key remains mounted only into the authorizer.

The provider-key file must contain exactly one valid 32-byte secp256k1 scalar
as 64 hex characters, with an optional final LF. Startup rejects zero,
out-of-range scalars, scalar 1, and scalar N-1. If the random value is rejected,
replace it with a newly generated value.

The enrollment token is a one-time 32–256 byte value. It is entered in the
browser for the first registration and is never logged or stored by the
browser. Do not put either file in this repository or in a shell history as
literal secret text.

Export a real 33-byte compressed backup public key from the independent
backup wallet. It must be independent of the hot and provider keys and must
not be generator G or its negation. Only the public key is supplied here;
generation and signing remain the backup wallet's responsibility.

## 2. Set deployment inputs

The example CSV delays below are explicit **demo policy choices**, not a
general custody recommendation. Mutinynet targets roughly 30-second blocks,
so 288 blocks is approximately 2.4 hours and 4032 blocks approximately 1.4
days. Reorganizations and block-time variance make wall-clock estimates
non-binding. Values must be in `1..65535`, and Savings must exceed Operational.

Replace `YOUR_REAL_DOMAIN` and `YOUR_REAL_EMAIL` below before running the
commands. The domain must be under DNS you control and resolve publicly to
this host; reserved `.test`/`.example` names cannot complete public ACME.

```bash
export YOUR_REAL_DOMAIN='YOUR_REAL_PUBLIC_DOMAIN'
export YOUR_REAL_EMAIL='YOUR_REAL_OPERATOR_EMAIL'
export VAULT_DOMAIN="vault.${YOUR_REAL_DOMAIN}"
export ACME_EMAIL="${YOUR_REAL_EMAIL}"
export VAULT_PROVIDER_KEY_FILE=/absolute/operator/path/vault-secrets/provider-key
export VAULT_ENROLLMENT_TOKEN_FILE=/absolute/operator/path/vault-secrets/enrollment-token
export VAULT_OFFLINE_PUB=02_REPLACE_WITH_REAL_66_HEX_COMPRESSED_BACKUP_PUB
export VAULT_OPERATIONAL_CSV_BLOCKS=288
export VAULT_SAVINGS_CSV_BLOCKS=4032
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

Open `https://$VAULT_DOMAIN` in a PRF-capable browser. Paste the contents of
the enrollment-token file into **One-time enrollment token**, then choose
**Create passkey + encrypted hot key**. Verify status reports:

- `enrolled: true`;
- `network: "mutinynet"`;
- the exact HTTPS `clientOrigin` and RP ID;
- `backupPub` exactly equal to `VAULT_OFFLINE_PUB`;
- the independently derived `providerBasePub` for the provider scalar;
- `arkadeEmulatorBasePub`, `arkadeEmulatorOrigin`, and
  `arkadeEmulatorVersion` exactly equal to the release pins above;
- distinct `tweakedProviderXOnly` and `tweakedArkadeXOnly` values;
- the intended template/policy versions and both CSV block delays;
- both `tb1p...` addresses and the configured economic caps; and
- both `savingsExcludesProvider: true` and
  `savingsExcludesCollaborators: true`.

Registration is first-write locked. Record this public status before funding.
The current POC exposes the immutable inputs but does not yet derive the full
descriptor independently in the browser; that remains a client milestone.

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
then choose **Passkey ceremony**. The page binds DirectP256, decrypts and uses
the hot key locally, and submits the hot-signed request. The authorizer first
persists the private Provider signature, then asks the pinned public Arkade
Emulator for its signature. The page accepts only its submitted hot signature
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
**Passkey ceremony** again. The page keeps the exact serialized authorize body
only in memory and resubmits those identical bytes; it does not generate a new
WebAuthn assertion, DirectP256 signature, or hot signature for the reserved
challenge. Reloading the page loses this retry material. A verified success or
any change of spend intent clears it. Assertion and PSBT material is never
written to `localStorage` or `sessionStorage`.

## 6. Restart proof

Restart only the protected authorizer and verify that descriptor and policy
state survive:

```bash
docker compose \
  -f poc/2fa-vault/docker-compose.mutinynet.yml \
  restart vault-authorizer
curl --fail --show-error https://$VAULT_DOMAIN/v1/status
```

Changing the provider key, backup key, network, CSV delays, client origin, RP
ID, template, or policy version must make restart fail rather than silently
derive a different vault. The credential/descriptor row carries a versioned
HMAC under a domain-separated key derived from the provider scalar. A private
Provider-key rotation therefore requires a reviewed migration with the old key
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

The current v2 credential and issuance schema is also exact. Pointing this
binary at a v1 database fails with migration/restore guidance; startup does not
rewrite the old descriptor, ledger, or already funded 2-of-2 UTXOs.

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
matching provider-key backup under the operator's encrypted secret process.

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
  to the one expected signature, but an outage can stop the collaborative
  path. Its `/v1/info` response has no network field; only the separate
  Esplora height-1 checkpoint pins Mutinynet.
- The browser independently derives and reconciles the restricted POC Arkade
  sighash, but does not yet derive a complete versioned vault descriptor.
- The backup wallet pairing/signing flow is not implemented here.
- This is one vault per isolated authorizer, with code-pinned economic caps.
- Container/root compromise is outside the protected-key claim.
- Database snapshots have no anti-rollback protection.

The next client milestone is specified in
[../../docs/arkade-wallet-vault-mode.md](../../docs/arkade-wallet-vault-mode.md).
