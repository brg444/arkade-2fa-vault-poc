# Arkade emulator + vault authorizer

This tree is the public Arkade **emulator** and `poc/2fa-vault/cmd/authorizer`.
It is Go source. It is not the product architecture home.

- Product client: [arkade-wallet-vault](https://github.com/brg444/arkade-wallet-vault)
- Protocol / docs map: [docs/architecture.md](https://github.com/brg444/arkade-wallet-vault/blob/vault-mode/docs/architecture.md)
- Deployable packaging: [arkade-vault-server](https://github.com/brg444/arkade-vault-server)

New enrolls are v5 only. Recovery is optional. Leftover v4 coins still
load until swept. Mutinynet only. Not an HSM. Not `poc/2fa-vault/web`.

Operate this binary: [poc/2fa-vault/README.md](poc/2fa-vault/README.md)

```bash
go test ./poc/2fa-vault/...
```
