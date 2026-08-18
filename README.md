# Arkade emulator

This tree is the public Arkade **emulator**. It is not the vault signer.

The Mutinynet authorizer lives in
[arkade-vault-server](https://github.com/brg444/arkade-vault-server)
(`cmd/authorizer`). Edit enroll and trees there.

- Product client: [arkade-wallet-vault](https://github.com/brg444/arkade-wallet-vault)
- Leftover in this tree: `poc/2fa-vault/cmd/provider`, `cmd/demo`, `web/` (regtest only)

`pkg/arkade` is the script engine the signer depends on. Do not treat
`poc/2fa-vault/cmd/authorizer` as a deployable. It exits and points at
vault-server.
