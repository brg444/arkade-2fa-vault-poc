# Vault server

Validating cosigner for the Mutinynet L1 Taproot vault. Not an Ark VTXO
service. Not an HSM. Not mainnet.

The **client** is the wallet vault-mode PWA. This package is the signer:
`cmd/authorizer` owns VaultCosigner and the SQLite ledger. The wallet is
hostile. This process decides.

**Enroll:** `phone-hww-recovery-staged-v5` only. Recovery is optional.  
Leftover v4 tenants still load until swept.

Operate: [deploy/mutinynet/README.md](deploy/mutinynet/README.md)  
Client spec: wallet `docs/README.md`  
Archive: [docs/archive/](docs/archive/)

## Two profiles

| Profile | Process | Keys |
| --- | --- | --- |
| Regtest | `cmd/provider` + two local Emulators | Public G/2G fixtures. Demo only. |
| Mutinynet | `cmd/authorizer` + allowlisted gateway | File-backed VaultCosigner. Invite `/v1/enroll/*`. No `/v1/register`. |

Live deploy is Railway `authorizer-next`. `web/` is not the product client.

## Live v4 trees

Daily: routine 3-of-3 (PhoneRoutine + two tweaked cosigners); admin
phone+hardware; CSV 144 device; CSV 6 hardware.  
Savings: admin + those two CSV leaves. No routine. No RecoveryKey.

Hardware can move first on a mature Savings coin. That hatch is why v5
exists. Do not mint new v4 after v5 enroll ships.

Routine script ends with:

```text
OP_0 OP_SIGHASH <0x11||directP256> OP_CHECKSIGFROMSTACK
```

Passkey does not sign Bitcoin. DirectP256 (PRF) signs the Arkade sighash.
PhoneRoutine is browser software, encrypted under the PRF. G and 2G are
rejected as on-chain keys.

## What Authorize checks

Hostile: request, PSBT, prevout, assertion, public-cosigner reply, publish
reply. Before either cosigner result is accepted:

- one Operational input, full previous transaction, exact Routine leaf
- one native-SegWit dest + mandatory non-dust recursive change
- packet + DirectP256 + PhoneRoutine over the same tx
- WebAuthn origin / RP / UP / UV
- fee, feerate, per-tx and period caps

Issuance is staged, not atomic:

```text
reserved → vault_signed → completed
```

Budget is reserved before VaultCosigner use. Exact retry resumes. A
changed request is rejected. Ambiguous reservations are never released.

Credential rows are HMAC-authenticated with a key HKDF-derived from the
VaultCosigner scalar. That detects DB drift. It is not anti-rollback.

## HTTP (Mutinynet)

`AuthorizerHandler` is the whole key-owning surface.

| Method | Paths |
| --- | --- |
| GET | `/health`, `/v1/status`, `/v1/tx`, `/v1/invite` |
| POST | `/v1/enroll/*`, `/v1/preflight`, `/v1/draft`, `/v1/bind`, `/v1/authorize`, `/v1/publish`, `/v1/passkey/*` |

Wrong method on a known path is 405. `/v1/register` is 404 here. Regtest
`NewHandler` still attaches register.

Leftover template `phone-direct-p256-routine-3of3-admin-2of2-v3` is
quarantined by **exact** match on multi-tenant boot. Any other stored
mismatch fails closed.

## v5 enroll (optional recovery)

New invites mint v4 unless a recovery key is supplied. With recovery,
propose rebuilds the 14-tree v5 family from phone, hardware, recovery,
DirectP256, and the two cosigner bases. Skip recovery and the authorizer
mints v4. Claim is never signed.

| Method | Path | Role |
| --- | --- | --- |
| POST | `/v1/enroll/propose` | Rebuilt v5 descriptor + hash |
| POST | `/v1/enroll/finish` | Persist daily/savings + recovery |
| POST | `/v1/initiate` | Cosign after dest + DecideReplay |
| POST | `/v1/clawback` | Cosign after dest + DecideReplay |

Shared goldens: Daily `tb1pp8ctf…`, Savings `tb1pze88n…`, pending
daily-recovery `tb1pauglx…`, descriptor hash
`f864eb57894578ef152e1e6d19550206b2c384d14e738c0d3206dde02e6ddcfa`.

See wallet [docs/plan.md](https://github.com/arkade-os/wallet) — local copy
in the vault-client repo.

## Claims

| Claim | Live status |
| --- | --- |
| Network caller uses a generic Mutinynet signer to skip policy | Closed. Constrained handler + one pinned outbound Arkade call |
| VaultCosigner use is bound to WebAuthn, tx, and budget | Yes, Routine |
| Host/root cannot extract VaultCosigner | No. Process isolation, not an HSM |
| Same-origin XSS is tolerated | No |
| Browser reconciles the Arkade sighash | Yes, one-input Routine |
| Browser / signer share a rebuilt v5 family | **In progress.** Client builds it; server executes fixture transitions and stores sessions. Enroll still mints v4. |
| Hardware/recovery key gen is in this repo | No |
| Cosigner stages are crash-atomic | Staged, not atomic |
| Mainnet / one vault per process | No mainnet. Live is invite multi-tenant |

## Tests

```bash
go test ./poc/2fa-vault/...
go test -race ./poc/2fa-vault/...
```

Pin Go 1.26.6.

Regtest publication uses Core 30+ (`version` ≥ `300000`). Confirm with
`docker exec bitcoin bitcoin-cli getnetworkinfo`. The authorizer treats
`testmempoolaccept` as the publish policy gate; other peers may still
reject the packet.
