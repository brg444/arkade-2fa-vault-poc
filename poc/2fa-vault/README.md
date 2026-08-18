# Leftover vault POC in the emulator tree

## About Arkade Vault

See the client [docs](https://github.com/brg444/arkade-wallet-vault/tree/vault-mode/docs).

## About this package

The live Mutinynet signer is
[arkade-vault-server](https://github.com/brg444/arkade-vault-server).
`cmd/authorizer` here exits and points there. Do not edit enroll or trees
in this package for production.

What remains here:

| Path | Role |
| --- | --- |
| `cmd/provider` | Regtest demo process |
| `cmd/demo` | Regtest demo |
| `web/` | Leftover static demo. Not the product client |
| `internal/*` | Leftover copies for those cmds. Live source is vault-server |

Client: [arkade-wallet-vault](https://github.com/brg444/arkade-wallet-vault).
