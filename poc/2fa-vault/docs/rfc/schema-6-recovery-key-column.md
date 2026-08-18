# SUPERSEDED

Use [schema-6-recovery-session.md](schema-6-recovery-session.md). Schema 6
is the v5 cutover (`recovery_session`). The leftover column decision lives
there.

---

# RFC: Schema 6 — leftover `recovery_key_compressed` column

Status: superseded. Do not implement as a standalone cleanup.

Live ledgers are schema 5 (`schema_meta.version = 5`) with issuance integrity
MACs. The `vault.recovery_key_compressed` column is still `NOT NULL` because
v4 enrollments persist a 33-byte placeholder. The public status, descriptor,
and trees do not expose a RecoveryKey.

This RFC exists so Schema 6 is not mixed into a cleanup PR.

## Decision required before approval

Choose exactly one:

1. **Nullable column.** `recovery_key_compressed BLOB NULL`. New enrollments
   write `NULL`. Leftover v3 rows keep their historical bytes until an
   operator deletes or migrates that vault. Safer rollback.
2. **Dropped column.** Remove the column after rewriting every v4 row. Smaller
   schema, harder rollback, requires old-binary rejection.

Do not approve both.

## Preconditions

- Exact schema-5 backup validation: `schema_meta.version = 5`, expected
  table/column/index/FK set from `expectedV4Tables`, and every loaded vault
  MAC verifies under the current VaultCosigner-derived integrity key.
- A `.pre-v6` copy of the live volume snapshot next to the operator secrets
  directory, not inside the Git checkout.
- Rehearsal against the current live snapshot (copy, not the production
  mount) before touching authorizer-next.
- Old binaries that expect schema 5 `NOT NULL` recovery bytes must refuse to
  open a schema-6 file.

## Transactional migration

One SQLite transaction:

1. Verify schema 5 and every vault/credential MAC.
2. For each vault, classify:
   - leftover template `phone-direct-p256-routine-3of3-admin-2of2-v3` — keep
     the historical recovery bytes if the column stays, or archive them
     out-of-band if the column is dropped;
   - live v4 template — write `NULL` or drop the placeholder.
3. Rewrite tables, bump `schema_meta.version` to 6, recompute integrity MACs
   if the encoded vault record changes.
4. Commit only if every rewritten MAC verifies.

A failed rehearsal leaves the production volume untouched.

## Out of scope

- Changing template `phone-direct-p256-routine-3of3-admin-phone-hww-v4`
- Changing policy `…onchain-v3`
- Changing CSV 144/6 or enroll CAS / MAC domains
- Adding a `vault_id` column to issuance (already multi-tenant)

## Verification for the later PR

- Container start from a schema-5 snapshot with the old binary still works.
- Container start from a migrated schema-6 snapshot with a pre-v6 binary
  fails closed.
- `go test -race ./poc/2fa-vault/...`
- Live `/v1/status` still has no `recoveryKeyPub`.
