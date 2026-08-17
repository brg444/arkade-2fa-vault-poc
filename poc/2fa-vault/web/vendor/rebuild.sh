#!/usr/bin/env bash
# Rebuild same-origin signing bundles from the pinned npm versions in NOTICE.md.
set -euo pipefail
cd "$(dirname "$0")"
WORKDIR="$(mktemp -d)"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

cd "$WORKDIR"
bun init -y >/dev/null
bun add @noble/curves@1.8.1 @scure/btc-signer@1.6.0 @noble/hashes@1.7.1 @scure/base@1.2.6 micro-packed@0.7.3

cat > secp256k1.entry.js <<'EOF'
export { secp256k1, schnorr } from "@noble/curves/secp256k1.js";
export { sha256 } from "@noble/hashes/sha256";
EOF
cat > p256.entry.js <<'EOF'
export { p256 } from "@noble/curves/p256.js";
EOF
cat > btc-signer.entry.js <<'EOF'
export {
  Transaction,
  SigHash,
  Address,
  OutScript,
  NETWORK,
  TEST_NETWORK,
} from "@scure/btc-signer";
EOF

OUT="$OLDPWD"
bun build ./secp256k1.entry.js --outfile "$OUT/secp256k1.js" --target=browser --format=esm --sourcemap=none
# Direct-auth P-256 must be a same-origin artifact, not a leftover entry file.
bun build ./p256.entry.js --outfile "$OUT/p256.js" --target=browser --format=esm --sourcemap=none
if [[ ! -s "$OUT/p256.js" ]]; then
  echo "rebuild.sh failed to produce p256.js" >&2
  exit 1
fi
bun build ./btc-signer.entry.js --outfile "$OUT/btc-signer.js" --target=browser --format=esm --sourcemap=none
cp node_modules/@noble/curves/LICENSE "$OUT/LICENSE.noble-curves"
cp node_modules/@scure/btc-signer/LICENSE "$OUT/LICENSE.scure-btc-signer"
cp node_modules/@noble/hashes/LICENSE "$OUT/LICENSE.noble-hashes"
cp node_modules/@scure/base/LICENSE "$OUT/LICENSE.scure-base"
cp node_modules/micro-packed/LICENSE "$OUT/LICENSE.micro-packed"
shasum -a 256 "$OUT/secp256k1.js" "$OUT/p256.js" "$OUT/btc-signer.js"
echo "Update NOTICE.md artifact checksums if these hashes changed."
