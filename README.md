# Arkade emulator

## About Arkade Vault

Mutinynet L1 Taproot vault. Architecture:
[arkade-wallet-vault/docs](https://github.com/brg444/arkade-wallet-vault/tree/vault-mode/docs).

## About this repo

This tree is the public Arkade **emulator** and `pkg/arkade` (script
opcodes). It is not the vault product.

| You want | Go here |
| --- | --- |
| Phone app | [arkade-wallet-vault](https://github.com/brg444/arkade-wallet-vault) |
| Signer / enroll / trees | [arkade-vault-server](https://github.com/brg444/arkade-vault-server) |
| Script engine | `pkg/arkade` in **this** repo |

`poc/2fa-vault/cmd/authorizer` exits and points at vault-server.
Leftover here: `cmd/provider`, `cmd/demo`, `web/` (regtest only).

```bash
go test ./poc/2fa-vault/...
```
