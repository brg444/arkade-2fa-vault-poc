# Vendored browser signing libraries

These files are served from the same origin as the vault page. The
decrypt-and-sign path must never load secp256k1 or PSBT code from a CDN.

Rebuilt with Bun from the exact npm versions below. Do not replace the
served files with an unpinned `esm.sh` / `unpkg` / `jsdelivr` import.

## Direct dependencies

| Package | Version | License | npm integrity | npm shasum |
|---|---|---|---|---|
| `@noble/curves` | 1.8.1 | MIT | `sha512-warwspo+UYUPep0Q+vtdVB4Ugn8GGQj8iyB3gnRWsztmUHTI3S1nhdiWNsPUGL0vud7JlRRk1XEu7Lq1KGTnMQ==` | `19bc3970e205c99e4bdb1c64a4785706bce497ff` |
| `@scure/btc-signer` | 1.6.0 | MIT | `sha512-qd6ciJE4Onk1xdQEdjPvRbLRrH7EddPZagMuZOFv77R/76EWixENd6nuoxqHNEPGRbS09rgAhhPgT7j0oQdi1A==` | `01796134be05507891f78f8536d99ce59a7cb559` |

## Transitive dependencies locked by those versions

| Package | Version | License | npm integrity | npm shasum |
|---|---|---|---|---|
| `@noble/hashes` | 1.7.1 | MIT | `sha512-B8XBPsn4vT/KJAGqDzbwztd+6Yte3P4V7iafm24bxgDe/mlRuK6xmWPuCNrKt2vDafZ8MfJLlchDG/vYafQEjQ==` | `5738f6d765710921e7a751e00c20ae091ed8db0f` |
| `@scure/base` | 1.2.6 | MIT | `sha512-g/nm5FgUa//MCj1gV09zTJTaM6KBAHqLN907YVQqf7zC49+DcO4B1so4ZX07Ef10Twr6nuqYEH9GEggFXA4Fmg==` | `ca917184b8231394dd8847509c67a0be522e59f6` |
| `micro-packed` | 0.7.3 | MIT | `sha512-2Milxs+WNC00TRlem41oRswvw31146GiSaoCT7s3Xi2gMUglW5QBeqlQaZeHr5tJx9nm3i57LNXPqxOOaWtTYg==` | `59e96b139dffeda22705c7a041476f24cabb12b6` |

## Served artifacts (SHA-256)

| File | SHA-256 |
|---|---|
| `secp256k1.js` | `fb7fc1a717b63b05864d75ff24598f5ca0ea26c3d99fb1514c84f35af75273d8` |
| `p256.js` | `0312baf2387b2d2b63a7b6145297517adf6ca0d62aed3ef46243e3f2913114cf` |
| `btc-signer.js` | `16a807a948955f9410d46a31a8056cf7e6886a87bc37f1de7b36ce1ce0d4ccb6` |

Licenses for each package are copied next to these files. Rebuild with
`./rebuild.sh` from this directory after changing versions, then update
the artifact checksums above.
