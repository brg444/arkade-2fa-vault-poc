package vault

import (
	"bytes"
	"crypto/elliptic"
	"fmt"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/txscript"
)

// AuthorizationScript is the static POC Arkade script:
//
//	OP_0 OP_SIGHASH <0x11 || compressed_direct_P256> OP_CHECKSIGFROMSTACK
//
// The initial stack is a single compact low-S 64-byte P-256 signature over
// the current transaction's Arkade sighash. The enrolled key is the
// PRF-derived direct-auth P-256 public key, never the WebAuthn credential
// ES256 public key. WebAuthn clientDataJSON/authenticatorData stay off-chain.
func AuthorizationScript(compressedDirectP256 []byte) ([]byte, error) {
	if err := parseCanonicalCompressedP256(compressedDirectP256); err != nil {
		return nil, err
	}
	key := append([]byte{0x11}, compressedDirectP256...)
	return txscript.NewScriptBuilder().
		AddOp(txscript.OP_0).
		AddOp(arkade.OP_SIGHASH).
		AddData(key).
		AddOp(arkade.OP_CHECKSIGFROMSTACK).
		Script()
}

// parseCanonicalCompressedP256 is a DirectP256 check, not a WebAuthn
// credential parse. It requires the unique compressed SEC1 encoding of an
// on-curve P-256 point.
func parseCanonicalCompressedP256(compressed []byte) error {
	if len(compressed) != 33 {
		return fmt.Errorf("compressed p256 key must be 33 bytes")
	}
	if compressed[0] != 0x02 && compressed[0] != 0x03 {
		return fmt.Errorf("direct p256 compressed prefix")
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), compressed)
	if x == nil {
		return fmt.Errorf("direct p256 point is off-curve")
	}
	if !bytes.Equal(elliptic.MarshalCompressed(elliptic.P256(), x, y), compressed) {
		return fmt.Errorf("direct p256 compressed encoding is not canonical")
	}
	return nil
}
