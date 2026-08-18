# Arkade emulator (this checkout)

This tree is the public Arkade emulator plus the **vault server** package
at [poc/2fa-vault](poc/2fa-vault).

The vault is an L1 Taproot validating cosigner on Mutinynet. It is not the
VTXO coordinator, not an HSM, and not mainnet. Never fund it with real BTC.

**Default enroll:** v4 (`phone-direct-p256-routine-3of3-admin-phone-hww-v4`).  
**Optional recovery:** v5 (`phone-hww-recovery-staged-v5`) when the tenant
supplies a recovery key. Skip recovery and enroll stays v4.

Start: [poc/2fa-vault/README.md](poc/2fa-vault/README.md)  
Operate: [poc/2fa-vault/deploy/mutinynet/README.md](poc/2fa-vault/deploy/mutinynet/README.md)

This repository is the emulator + authorizer source. The product client
and the protocol docs live in the vault-mode wallet. The deployable
packaging surface is `arkade-vault-server`. Do not treat `poc/2fa-vault/web`
as the live PWA.

## Two vault profiles

| Profile | Purpose | VaultCosigner |
| --- | --- | --- |
| Regtest | Local demo, fixtures, mining | `cmd/provider` + two disposable Emulators |
| Mutinynet | Internet POC | `cmd/authorizer` only; one outbound HTTPS to the pinned public Arkade cosigner |

No generic inbound signer. No `/v1/register` on Mutinynet. Enrollment is
invite-gated. The product client is wallet vault mode, not `poc/2fa-vault/web`.

## Live v4 trees

Ordinary Taproot UTXOs, not VTXOs.

| Vault | Leaves |
| --- | --- |
| Daily | Routine 3-of-3 phone + two tweaked cosigners; admin phone+hardware; CSV 144 device; CSV 6 hardware |
| Savings | Admin + the same two CSV leaves. No routine. No RecoveryKey |

Hardware can move first. That is an attacker hatch on mature Savings. v5
removes singlesig CSV from Normal.

## Security claims

| Claim | Live status |
| --- | --- |
| A network caller can bypass private policy through a generic signer on Mutinynet | **Closed.** Constrained authorizer; tests reject generic Emulator/gRPC and demo signing surfaces. One outbound call to the pinned Arkade endpoint, reduced to one verified signature. |
| VaultCosigner-key use is bound to WebAuthn, transaction, and budget checks | **Yes** for Routine. Key and ledger share one process; budget is reserved first. |
| Host/root cannot extract or misuse VaultCosigner | **No.** Docker/Railway is process isolation, not an HSM. |
| Compromised same-origin frontend is tolerated | **No.** Unlocked PhoneRoutine or PRF is stealable. Hardware signing exists; it does not make a hostile first-party bundle safe. |
| Browser independently derives and reconciles the Arkade sighash | **Yes** for the one-input Routine template. |
| Browser independently derives the complete versioned descriptor | **v4:** client hashes the proposed descriptor and rebuilds Savings. Daily `Q` still comes from the authorizer. **v5:** authorizer rebuilds the 14-tree family on propose when recovery is supplied. |
| Hardware / recovery ceremonies are implemented | **Signing/handoff yes for v4 hardware.** Key generation is out of repo. Recovery is optional. v5 recovery is a third guardian, not a v4 RecoveryKey leaf. |
| Cosigner stages are crash-atomic | **Staged, not atomic.** `reserved → vault_signed → completed`. |
| Mainnet readiness | **No.** Mutinynet only. Live authorizer is invite **multi-tenant**, not one vault per process. |

## Tests

```bash
go test ./poc/2fa-vault/...
```
