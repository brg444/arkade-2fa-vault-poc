Browser assertion fixtures live here.

Generate:

```
cd poc/2fa-vault/web/e2e && bunx playwright install chromium && bun capture.mjs
```

This writes `webauthn_get.json` from a Chrome virtual authenticator. Until that file exists, `TestBrowserAssertionFixture` skips.

A captured assertion is **off-chain** Provider evidence (origin/RP/UV/ES256). It is not the Arkade packet witness. On-chain authorization is a DirectP256 compact signature over `OP_SIGHASH`.

`TestArkadePacketOnchainPolicy` does not need this fixture. It measures the
on-chain packet with a one-item DirectP256 witness and, when `nigiri` is up,
broadcasts against the live regtest node policy.
