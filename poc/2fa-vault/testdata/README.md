Browser assertion fixtures live here.

Generate:

```
make vault-browser-fixture
```

This uses Bun and Chrome's DevTools Protocol directly; Playwright is not
required. It requires a 32-byte PRF result inside the browser page but never
serializes or logs those bytes. It writes only the public WebAuthn ES256
assertion to `webauthn_get.json`, then runs the Go consumer tests. Set
`CHROME_BIN` if Chrome is not installed in a standard location. Until that
file exists, `TestBrowserAssertionFixture` skips.

A captured assertion is **off-chain** Provider evidence (origin/RP/UV/ES256). It is not the Arkade packet witness. On-chain authorization is a DirectP256 compact signature over `OP_SIGHASH`.

`TestArkadePacketOnchainPolicy` does not need this fixture. It measures the
on-chain packet with a one-item DirectP256 witness and, when `nigiri` is up,
broadcasts against the live regtest node policy.
