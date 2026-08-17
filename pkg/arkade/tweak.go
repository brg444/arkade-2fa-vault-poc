package arkade

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var (
	TagArkScriptHash  = []byte("ArkScriptHash")
	TagArkWitnessHash = []byte("ArkWitnessHash")
)

// ArkadeScriptHash computes the hash of an ark script.
// scripthash = h_arkScriptHash(script)
func ArkadeScriptHash(script []byte) []byte {
	hash := chainhash.TaggedHash(TagArkScriptHash, script)
	return hash[:]
}

// ComputeArkadeScriptPublicKey calculates a top-level ark script public key given the hash of the arkscript
func ComputeArkadeScriptPublicKey(pubKey *btcec.PublicKey, scriptHash []byte) *btcec.PublicKey {
	pubKey, _ = schnorr.ParsePubKey(schnorr.SerializePubKey(pubKey))

	var (
		pubKeyJacobian btcec.JacobianPoint
		tweakJacobian  btcec.JacobianPoint
		resultJacobian btcec.JacobianPoint
	)
	tweakKey, _ := btcec.PrivKeyFromBytes(scriptHash)
	if tweakKey.Key.IsZero() {
		return nil
	}
	btcec.ScalarBaseMultNonConst(&tweakKey.Key, &tweakJacobian)

	pubKey.AsJacobian(&pubKeyJacobian)
	btcec.AddNonConst(&pubKeyJacobian, &tweakJacobian, &resultJacobian)
	if resultJacobian.Z.IsZero() {
		return nil
	}

	resultJacobian.ToAffine()
	return btcec.NewPublicKey(&resultJacobian.X, &resultJacobian.Y)
}

func ComputeArkadeScriptPrivateKey(privKey *btcec.PrivateKey, scriptHash []byte) *btcec.PrivateKey {
	privKeyScalar := privKey.Key
	pubKeyBytes := privKey.PubKey().SerializeCompressed()
	if pubKeyBytes[0] == secp256k1.PubKeyFormatCompressedOdd {
		privKeyScalar.Negate()
	}

	tweakScalar := new(btcec.ModNScalar)
	tweakScalar.SetByteSlice(scriptHash)
	if tweakScalar.IsZero() {
		return nil
	}

	tweakScalar.Add(&privKeyScalar)
	if tweakScalar.IsZero() {
		return nil
	}

	return &btcec.PrivateKey{Key: *tweakScalar}
}
