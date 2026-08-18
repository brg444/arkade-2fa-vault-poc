# Arkade emulator

This repo is the Arkade **script engine** (`pkg/arkade`). It is not the
vault app and not the vault service.

| You want | Go here |
| --- | --- |
| Phone app | [arkade-wallet-vault](https://github.com/brg444/arkade-wallet-vault) |
| Vault service | [arkade-vault-server](https://github.com/brg444/arkade-vault-server) |
| Script opcodes | `pkg/arkade` here |

The old `poc/2fa-vault/cmd/authorizer` just exits and tells you to use
vault-server. What’s left here (`cmd/provider`, `cmd/demo`, `web/`) is
regtest leftover.

```bash
go test ./poc/2fa-vault/...
```
