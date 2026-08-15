package provider

import (
	"bytes"
	"fmt"

	"github.com/arkade-os/emulator/poc/2fa-vault/internal/vault"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
)

// verifyHotSignature requires a BIP342 SIGHASH_DEFAULT signature from the
// enrolled hot key over the collaborative leaf of the exact current tx.
func verifyHotSignature(ptx *psbt.Packet, op *vault.Built) error {
	if op == nil || op.Leaves.Collaborative == nil || op.Record.Hot == nil {
		return fmt.Errorf("operational vault not ready")
	}
	if ptx.Inputs[0].WitnessUtxo == nil {
		return fmt.Errorf("missing witness utxo")
	}
	wantPub := schnorr.SerializePubKey(op.Record.Hot)
	wantLeaf := op.Leaves.Collaborative.Hash
	if len(ptx.Inputs[0].TaprootScriptSpendSig) != 1 || ptx.Inputs[0].TaprootScriptSpendSig[0] == nil {
		return fmt.Errorf("expected exactly one hot signature")
	}
	s := ptx.Inputs[0].TaprootScriptSpendSig[0]
	if !bytes.Equal(s.XOnlyPubKey, wantPub) || !bytes.Equal(s.LeafHash, wantLeaf) {
		return fmt.Errorf("unexpected taproot signature")
	}
	if s.SigHash != txscript.SigHashDefault {
		return fmt.Errorf("hot signature sighash")
	}
	sig := s.Signature
	if len(sig) != 64 {
		return fmt.Errorf("missing hot signature")
	}
	prev := ptx.Inputs[0].WitnessUtxo
	fetcher := vault.NewPrevFetcher(ptx.UnsignedTx.TxIn[0].PreviousOutPoint, prev)
	sigHashes := txscript.NewTxSigHashes(ptx.UnsignedTx, fetcher)
	leaf := txscript.NewBaseTapLeaf(op.Leaves.Collaborative.Script)
	digest, err := txscript.CalcTapscriptSignaturehash(
		sigHashes, txscript.SigHashDefault, ptx.UnsignedTx, 0, fetcher, leaf,
	)
	if err != nil {
		return fmt.Errorf("hot sighash: %w", err)
	}
	parsed, err := schnorr.ParseSignature(sig)
	if err != nil {
		return fmt.Errorf("hot signature: %w", err)
	}
	pub, err := schnorr.ParsePubKey(wantPub)
	if err != nil {
		return err
	}
	if !parsed.Verify(digest, pub) {
		return fmt.Errorf("hot signature invalid")
	}
	return nil
}
