# RFC: Schema 6 — v5 next product

Status: draft. Required before live v5 enroll. Not a cleanup PR.

Live ledgers are schema 5. v4 rows keep a `NOT NULL`
`recovery_key_compressed` placeholder the public API does not expose.

v5 needs a **sign-once** table for initiate/clawback:

```text
recovery_session (
  vault_id, outpoint, purpose,  -- purpose in (initiate, clawback)
  dest_script, last_sighash, signature, ...
)
```

Same dest + same input + higher fee → re-sign. Different dest or extra
input → nothing. Never persist `claim`.

## Leftover column (decide in this RFC, implement with v5)

Choose one:

1. **Nullable** `recovery_key_compressed`. New v5 rows write `NULL`. Safer rollback.
2. **Dropped** after rewriting v4 placeholders. Smaller schema, harder rollback.

Do not do both. Old binaries that expect schema 5 `NOT NULL` must refuse
schema 6.

## Preconditions

- Exact schema-5 backup (`.pre-v6`), MAC verify, rehearsal on a **copy**
  of the live snapshot
- Go/TS goldens for the v5 family before cutover
- Leftover v3 template still quarantined by exact match

## Out of scope

- Changing live v4 template or CSV 144/6 for existing UTXOs
- Dropping invite enroll
- VTXO
