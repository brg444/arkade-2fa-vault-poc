package provider

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/arkade-os/emulator/poc/2fa-vault/internal/vault"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
)

func clonePacket(p *psbt.Packet) (*psbt.Packet, error) {
	if p == nil {
		return nil, fmt.Errorf("psbt required")
	}
	encoded, err := p.B64Encode()
	if err != nil {
		return nil, err
	}
	return psbt.NewFromRawBytes(strings.NewReader(encoded), true)
}

func cloneSpendSig(s *psbt.TaprootScriptSpendSig) *psbt.TaprootScriptSpendSig {
	if s == nil {
		return nil
	}
	return &psbt.TaprootScriptSpendSig{
		XOnlyPubKey: append([]byte(nil), s.XOnlyPubKey...),
		LeafHash:    append([]byte(nil), s.LeafHash...),
		Signature:   append([]byte(nil), s.Signature...),
		SigHash:     s.SigHash,
	}
}

// extractVerifiedProviderSig returns the single new provider Taproot script
// spend signature from an Emulator response. Verification is against the
// immutable submitted packet, not the response's possibly mutated fields.
func extractVerifiedProviderSig(submitted, response *psbt.Packet, expectedProvider []byte) (*psbt.TaprootScriptSpendSig, error) {
	if submitted == nil || submitted.UnsignedTx == nil || len(submitted.Inputs) != 1 || len(submitted.UnsignedTx.TxIn) != 1 {
		return nil, fmt.Errorf("exactly one submitted input required")
	}
	if response == nil || response.UnsignedTx == nil || len(response.Inputs) != 1 || len(response.UnsignedTx.TxIn) != 1 {
		return nil, fmt.Errorf("malformed signed psbt")
	}
	if len(expectedProvider) != 32 {
		return nil, fmt.Errorf("expected provider x-only key")
	}
	in := submitted.Inputs[0]
	if in.WitnessUtxo == nil || len(in.TaprootLeafScript) != 1 || in.TaprootLeafScript[0] == nil {
		return nil, fmt.Errorf("submitted input missing leaf commitment")
	}
	leaf := txscript.NewBaseTapLeaf(in.TaprootLeafScript[0].Script)
	leafHash := leaf.TapHash()

	var extras []*psbt.TaprootScriptSpendSig
	matched := make([]bool, len(in.TaprootScriptSpendSig))
	for _, s := range response.Inputs[0].TaprootScriptSpendSig {
		if i := indexOriginalSig(in.TaprootScriptSpendSig, s); i >= 0 && !matched[i] {
			matched[i] = true
			continue
		}
		extras = append(extras, s)
	}

	var found *psbt.TaprootScriptSpendSig
	for _, extra := range extras {
		if extra == nil || len(extra.Signature) != 64 {
			continue
		}
		if !bytes.Equal(extra.XOnlyPubKey, expectedProvider) {
			continue
		}
		if !bytes.Equal(extra.LeafHash, leafHash[:]) {
			continue
		}
		if extra.SigHash != txscript.SigHashDefault {
			continue
		}
		if err := verifyProviderSig(submitted, extra, expectedProvider, leaf); err != nil {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("expected exactly one new provider signature, got extra")
		}
		found = extra
	}
	if found == nil {
		return nil, fmt.Errorf("expected exactly one new provider signature")
	}
	return cloneSpendSig(found), nil
}

func verifyProviderSig(submitted *psbt.Packet, found *psbt.TaprootScriptSpendSig, expectedProvider []byte, leaf txscript.TapLeaf) error {
	prev := submitted.Inputs[0].WitnessUtxo
	fetcher := vault.NewPrevFetcher(submitted.UnsignedTx.TxIn[0].PreviousOutPoint, prev)
	digest, err := txscript.CalcTapscriptSignaturehash(
		txscript.NewTxSigHashes(submitted.UnsignedTx, fetcher),
		txscript.SigHashDefault, submitted.UnsignedTx, 0, fetcher, leaf,
	)
	if err != nil {
		return err
	}
	sig, err := schnorr.ParseSignature(found.Signature)
	if err != nil {
		return err
	}
	pub, err := schnorr.ParsePubKey(expectedProvider)
	if err != nil {
		return err
	}
	if !sig.Verify(digest, pub) {
		return fmt.Errorf("provider signature invalid")
	}
	return nil
}

func indexOriginalSig(before []*psbt.TaprootScriptSpendSig, s *psbt.TaprootScriptSpendSig) int {
	if s == nil {
		return -1
	}
	for i, want := range before {
		if want == nil {
			continue
		}
		if bytes.Equal(s.XOnlyPubKey, want.XOnlyPubKey) &&
			bytes.Equal(s.LeafHash, want.LeafHash) &&
			bytes.Equal(s.Signature, want.Signature) &&
			s.SigHash == want.SigHash {
			return i
		}
	}
	return -1
}
