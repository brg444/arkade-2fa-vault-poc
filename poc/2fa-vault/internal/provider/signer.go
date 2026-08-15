package provider

import (
	"bytes"
	"context"
	"fmt"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/emulator/pkg/client"
	"github.com/arkade-os/emulator/poc/2fa-vault/internal/vault"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
)

// Signer adds the tweaked Provider signature after the Arkade script succeeds.
type Signer interface {
	Sign(ctx context.Context, ptx *psbt.Packet) (*psbt.Packet, error)
}

// LocalSigner executes the committed DirectP256 OP_SIGHASH script and
// BIP340-signs locally. Test-only or -unsafe-local-signer. Deployment uses
// RemoteSigner. The script binds the packet witness to the current Arkade
// sighash; it does not verify WebAuthn or enforce budget.
type LocalSigner struct {
	Priv *btcec.PrivateKey
}

func (s LocalSigner) Sign(_ context.Context, ptx *psbt.Packet) (*psbt.Packet, error) {
	if s.Priv == nil {
		return nil, fmt.Errorf("local signer missing private key")
	}
	if ptx == nil || ptx.UnsignedTx == nil || len(ptx.Inputs) != 1 || len(ptx.UnsignedTx.TxIn) != 1 {
		return nil, fmt.Errorf("exactly one input required")
	}
	if ptx.Inputs[0].WitnessUtxo == nil {
		return nil, fmt.Errorf("witness utxo required")
	}
	if len(ptx.Inputs[0].TaprootLeafScript) == 0 || ptx.Inputs[0].TaprootLeafScript[0] == nil {
		return nil, fmt.Errorf("taproot leaf script required")
	}
	packet, err := arkade.FindEmulatorPacket(ptx.UnsignedTx)
	if err != nil {
		return nil, err
	}
	if len(packet) != 1 {
		return nil, fmt.Errorf("expected one emulator entry")
	}
	script, err := arkade.ReadArkadeScript(ptx, s.Priv.PubKey(), packet[0])
	if err != nil {
		return nil, err
	}
	prevTx, err := vault.RequireVerifiedPrevout(ptx)
	if err != nil {
		return nil, err
	}
	prev := ptx.Inputs[0].WitnessUtxo
	fetcher := vault.NewPrevFetcher(ptx.UnsignedTx.TxIn[0].PreviousOutPoint, prev).WithPrevTx(prevTx)
	if err := script.Execute(ptx.UnsignedTx, fetcher, 0); err != nil {
		return nil, fmt.Errorf("arkade script: %w", err)
	}

	tweak := script.Hash()
	key := arkade.ComputeArkadeScriptPrivateKey(s.Priv, tweak)
	if ptx.Inputs[0].SighashType != txscript.SigHashDefault {
		return nil, fmt.Errorf("unsupported sighash")
	}
	if err := arkade.VerifyTaprootLeafCommitment(prev.PkScript, ptx.Inputs[0].TaprootLeafScript[0]); err != nil {
		return nil, err
	}
	leaf := txscript.NewBaseTapLeaf(ptx.Inputs[0].TaprootLeafScript[0].Script)
	sigHashes := txscript.NewTxSigHashes(ptx.UnsignedTx, fetcher)
	sig, err := txscript.RawTxInTapscriptSignature(
		ptx.UnsignedTx, sigHashes, 0, prev.Value, prev.PkScript, leaf, txscript.SigHashDefault, key,
	)
	if err != nil {
		return nil, err
	}
	if len(sig) == 65 {
		sig = sig[:64]
	}
	h := leaf.TapHash()
	ptx.Inputs[0].TaprootScriptSpendSig = append(ptx.Inputs[0].TaprootScriptSpendSig, &psbt.TaprootScriptSpendSig{
		Signature:   sig,
		XOnlyPubKey: schnorr.SerializePubKey(key.PubKey()),
		LeafHash:    h[:],
		SigHash:     txscript.SigHashDefault,
	})
	return ptx, nil
}

// RemoteSigner calls the private Emulator SubmitOnchainTx endpoint.
type RemoteSigner struct {
	Client        client.TransportClient
	ExpectedXOnly []byte
}

func (s *RemoteSigner) Sign(ctx context.Context, ptx *psbt.Packet) (*psbt.Packet, error) {
	if s == nil {
		return nil, fmt.Errorf("remote signer required")
	}
	if s.Client == nil {
		return nil, fmt.Errorf("remote signer missing client")
	}
	if len(s.ExpectedXOnly) != 32 {
		return nil, fmt.Errorf("remote signer missing expected provider key")
	}
	if ptx == nil || ptx.UnsignedTx == nil || len(ptx.Inputs) != 1 || len(ptx.UnsignedTx.TxIn) != 1 {
		return nil, fmt.Errorf("exactly one input required")
	}
	encoded, err := ptx.B64Encode()
	if err != nil {
		return nil, err
	}
	signed, err := s.Client.SubmitOnchainTx(ctx, encoded)
	if err != nil {
		return nil, err
	}
	out, err := psbt.NewFromRawBytes(bytes.NewReader([]byte(signed)), true)
	if err != nil {
		return nil, err
	}
	providerSig, err := extractVerifiedProviderSig(ptx, out, s.ExpectedXOnly)
	if err != nil {
		return nil, err
	}
	clone, err := clonePacket(ptx)
	if err != nil {
		return nil, err
	}
	if clone == nil || len(clone.Inputs) != 1 {
		return nil, fmt.Errorf("cloned packet missing input")
	}
	clone.Inputs[0].TaprootScriptSpendSig = append(clone.Inputs[0].TaprootScriptSpendSig, providerSig)
	return clone, nil
}
