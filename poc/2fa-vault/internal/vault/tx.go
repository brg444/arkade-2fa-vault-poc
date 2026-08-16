package vault

import (
	"bytes"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/emulator/poc/2fa-vault/fixture"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// SpendParams describes one Operational collaborative spend.
type SpendParams struct {
	Vault           *Built
	PrevTx          *wire.MsgTx
	PrevOutPoint    wire.OutPoint
	RecipientScript []byte
	RecipientAmount int64
	Fee             int64
	Sequence        uint32
	Witness         wire.TxWitness // empty for challenge computation
}

// BuiltSpend is the unsigned/collaborative PSBT plus derived digests.
type BuiltSpend struct {
	Packet       *psbt.Packet
	Challenge    []byte
	ChangeAmount int64
	HasChange    bool
	InputValue   int64
	Prevout      *wire.TxOut
}

// BuildCollaborativeSpend builds the exact one-in / recipient / optional change
// / packet-out template. The emulator packet witness is params.Witness.
func BuildCollaborativeSpend(p SpendParams) (*BuiltSpend, error) {
	if p.Vault == nil || p.Vault.Leaves.Collaborative == nil {
		return nil, fmt.Errorf("operational collaborative leaf required")
	}
	if len(p.RecipientScript) == 0 {
		return nil, fmt.Errorf("recipient script required")
	}
	if !txscript.IsWitnessProgram(p.RecipientScript) {
		return nil, fmt.Errorf("collaborative recipient must be a native segwit output")
	}
	prev, err := checkedPrevout(p.Vault, p.PrevTx, p.PrevOutPoint)
	if err != nil {
		return nil, err
	}
	if p.Fee < 0 || p.RecipientAmount <= 0 {
		return nil, fmt.Errorf("invalid amount")
	}
	if p.RecipientAmount < p.Vault.Record.AuthorizationPolicy.RecipientDustSats {
		return nil, fmt.Errorf("recipient below dust")
	}

	change, err := remainingAfter(prev.Value, p.RecipientAmount, p.Fee)
	if err != nil {
		return nil, err
	}
	hasChange := change > 0
	if hasChange && change < p.Vault.Record.AuthorizationPolicy.RecipientDustSats {
		return nil, fmt.Errorf("change below dust")
	}

	tx := wire.NewMsgTx(2)
	seq := p.Sequence
	if seq == 0 {
		seq = wire.MaxTxInSequenceNum
	}
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: p.PrevOutPoint,
		Sequence:         seq,
	})
	tx.AddTxOut(&wire.TxOut{Value: p.RecipientAmount, PkScript: p.RecipientScript})
	if hasChange {
		tx.AddTxOut(&wire.TxOut{Value: change, PkScript: p.Vault.PkScript})
	}

	entry := arkade.EmulatorEntry{
		Vin:     0,
		Script:  p.Vault.Record.AuthScript,
		Witness: p.Witness,
	}
	if err := attachPacket(tx, entry); err != nil {
		return nil, err
	}

	packet, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		return nil, err
	}
	packet.Inputs[0].WitnessUtxo = &wire.TxOut{Value: prev.Value, PkScript: prev.PkScript}
	packet.Inputs[0].SighashType = txscript.SigHashDefault
	packet.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		ControlBlock: p.Vault.Leaves.Collaborative.ControlBlock,
		Script:       p.Vault.Leaves.Collaborative.Script,
		LeafVersion:  txscript.BaseLeafVersion,
	}}
	if err := txutils.SetArkPsbtField(packet, 0, arkade.PrevoutTxField, *p.PrevTx); err != nil {
		return nil, err
	}

	challenge, err := Challenge(packet, p.Vault)
	if err != nil {
		return nil, err
	}
	return &BuiltSpend{
		Packet:       packet,
		Challenge:    challenge,
		ChangeAmount: change,
		HasChange:    hasChange,
		InputValue:   prev.Value,
		Prevout:      prev,
	}, nil
}

func attachPacket(tx *wire.MsgTx, entry arkade.EmulatorEntry) error {
	pkt, err := arkade.NewPacket(entry)
	if err != nil {
		return err
	}
	ext := extension.Extension{pkt}
	out, err := ext.TxOut()
	if err != nil {
		return err
	}
	if out.Value != 0 {
		return fmt.Errorf("emulator packet output must be zero value")
	}
	tx.AddTxOut(out)
	return nil
}

// Challenge is the witness-masked Arkade SIGHASH_DEFAULT digest.
func Challenge(ptx *psbt.Packet, vault *Built) ([]byte, error) {
	if len(ptx.UnsignedTx.TxIn) != 1 || len(ptx.Inputs) != 1 {
		return nil, fmt.Errorf("expected one input")
	}
	prev := ptx.Inputs[0].WitnessUtxo
	if prev == nil {
		return nil, fmt.Errorf("missing witness utxo")
	}
	fetcher := NewPrevFetcher(ptx.UnsignedTx.TxIn[0].PreviousOutPoint, prev)
	leaf := txscript.NewBaseTapLeaf(vault.Leaves.Collaborative.Script)
	sigHashes := txscript.NewTxSigHashes(ptx.UnsignedTx, fetcher)
	return arkade.CalcArkadeScriptSignatureHash(
		sigHashes, txscript.SigHashDefault, ptx.UnsignedTx, 0, fetcher, leaf,
	)
}

// SetPacketWitness replaces the emulator packet witness and leaves the
// challenge unchanged (witness bytes are masked).
func SetPacketWitness(tx *wire.MsgTx, witness wire.TxWitness) error {
	entry, script, err := packetEntry(tx)
	if err != nil {
		return err
	}
	entry.Witness = witness
	// Rebuild the extension output in place.
	for i, out := range tx.TxOut {
		if !extension.IsExtension(out.PkScript) {
			continue
		}
		pkt, err := arkade.NewPacket(arkade.EmulatorEntry{
			Vin:     entry.Vin,
			Script:  script,
			Witness: witness,
		})
		if err != nil {
			return err
		}
		ext := extension.Extension{pkt}
		repl, err := ext.TxOut()
		if err != nil {
			return err
		}
		tx.TxOut[i] = repl
		return nil
	}
	return fmt.Errorf("emulator packet output not found")
}

func packetEntry(tx *wire.MsgTx) (arkade.EmulatorEntry, []byte, error) {
	packet, err := arkade.FindEmulatorPacket(tx)
	if err != nil {
		return arkade.EmulatorEntry{}, nil, err
	}
	if len(packet) != 1 {
		return arkade.EmulatorEntry{}, nil, fmt.Errorf("expected one emulator entry")
	}
	return packet[0], packet[0].Script, nil
}

// PrevFetcher implements arkade.ArkPrevOutFetcher for a single verified prevout.
type PrevFetcher struct {
	txscript.PrevOutputFetcher
	op  wire.OutPoint
	tx  *wire.MsgTx
	idx uint32
}

// NewPrevFetcher wraps one outpoint/output.
func NewPrevFetcher(op wire.OutPoint, out *wire.TxOut) *PrevFetcher {
	return &PrevFetcher{
		PrevOutputFetcher: txscript.NewCannedPrevOutputFetcher(out.PkScript, out.Value),
		op:                op,
		idx:               op.Index,
	}
}

// WithPrevTx attaches the verified previous transaction for FetchPrevOutArkTx.
func (f *PrevFetcher) WithPrevTx(tx *wire.MsgTx) *PrevFetcher {
	f.tx = tx
	return f
}

func (f *PrevFetcher) FetchPrevOutArkTx(op wire.OutPoint) *wire.MsgTx {
	if op != f.op {
		return nil
	}
	return f.tx
}

func (f *PrevFetcher) FetchVtxoPrevOutPkScript(op wire.OutPoint) []byte {
	if op != f.op || f.tx == nil {
		return nil
	}
	if int(f.idx) >= len(f.tx.TxOut) {
		return nil
	}
	return f.tx.TxOut[f.idx].PkScript
}

// SignLeaf produces a BIP342 SIGHASH_DEFAULT tapscript signature.
func SignLeaf(tx *wire.MsgTx, prev *wire.TxOut, leafScript []byte, priv *btcec.PrivateKey) ([]byte, error) {
	fetcher := txscript.NewCannedPrevOutputFetcher(prev.PkScript, prev.Value)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)
	leaf := txscript.NewBaseTapLeaf(leafScript)
	sig, err := txscript.RawTxInTapscriptSignature(
		tx, sigHashes, 0, prev.Value, prev.PkScript, leaf, txscript.SigHashDefault, priv,
	)
	if err != nil {
		return nil, err
	}
	if len(sig) == 65 {
		return sig[:64], nil
	}
	return sig, nil
}

// AddPartialSig appends a taproot script spend signature to the PSBT input.
func AddPartialSig(ptx *psbt.Packet, pub *btcec.PublicKey, leafHash, sig []byte) {
	ptx.Inputs[0].TaprootScriptSpendSig = append(ptx.Inputs[0].TaprootScriptSpendSig, &psbt.TaprootScriptSpendSig{
		XOnlyPubKey: schnorr.SerializePubKey(pub),
		LeafHash:    leafHash,
		Signature:   sig,
		SigHash:     txscript.SigHashDefault,
	})
}

// FinalizeCollaborative builds the Bitcoin witness from the hot, private
// Provider, and public Arkade Emulator partial signatures.
// It fail-closes on nil inputs, a preexisting final script, the wrong leaf,
// duplicate/extra keys, a non-default sighash, or an invalid signature.
func FinalizeCollaborative(ptx *psbt.Packet, v *Built) error {
	if err := verifyCollaborativePartials(ptx, v); err != nil {
		return err
	}
	return writeFinalWitness(ptx, v.Leaves.Collaborative)
}

func verifyCollaborativePartials(ptx *psbt.Packet, v *Built) error {
	if ptx == nil || ptx.UnsignedTx == nil || v == nil || v.Leaves.Collaborative == nil || v.Record.Hot == nil || v.TweakedProvider == nil || v.TweakedArkade == nil {
		return fmt.Errorf("collaborative finalize inputs")
	}
	if len(ptx.Inputs) != 1 || len(ptx.UnsignedTx.TxIn) != 1 {
		return fmt.Errorf("exactly one input required")
	}
	in := &ptx.Inputs[0]
	if len(in.FinalScriptWitness) != 0 || len(in.FinalScriptSig) != 0 {
		return fmt.Errorf("preexisting final script")
	}
	if in.WitnessUtxo == nil {
		return fmt.Errorf("witness utxo required")
	}
	if len(in.TaprootLeafScript) != 1 || in.TaprootLeafScript[0] == nil {
		return fmt.Errorf("exactly one taproot leaf required")
	}
	leaf := in.TaprootLeafScript[0]
	if !bytes.Equal(leaf.Script, v.Leaves.Collaborative.Script) || !bytes.Equal(leaf.ControlBlock, v.Leaves.Collaborative.ControlBlock) {
		return fmt.Errorf("leaf is not the collaborative path")
	}
	if leaf.LeafVersion != txscript.BaseLeafVersion {
		return fmt.Errorf("unsupported leaf version")
	}
	wantHot := schnorr.SerializePubKey(v.Record.Hot)
	wantProv := schnorr.SerializePubKey(v.TweakedProvider)
	wantArkade := schnorr.SerializePubKey(v.TweakedArkade)
	wantLeaf := v.Leaves.Collaborative.Hash
	var hotSig, provSig, arkadeSig *psbt.TaprootScriptSpendSig
	seen := make(map[string]struct{})
	for _, s := range in.TaprootScriptSpendSig {
		if s == nil {
			return fmt.Errorf("nil taproot signature")
		}
		key := string(s.XOnlyPubKey) + string(s.LeafHash)
		if _, ok := seen[key]; ok {
			return fmt.Errorf("duplicate taproot signature")
		}
		seen[key] = struct{}{}
		if s.SigHash != txscript.SigHashDefault {
			return fmt.Errorf("unsupported sighash")
		}
		if !bytes.Equal(s.LeafHash, wantLeaf) {
			return fmt.Errorf("wrong leaf hash")
		}
		switch {
		case bytes.Equal(s.XOnlyPubKey, wantHot):
			if hotSig != nil {
				return fmt.Errorf("duplicate hot signature")
			}
			hotSig = s
		case bytes.Equal(s.XOnlyPubKey, wantProv):
			if provSig != nil {
				return fmt.Errorf("duplicate provider signature")
			}
			provSig = s
		case bytes.Equal(s.XOnlyPubKey, wantArkade):
			if arkadeSig != nil {
				return fmt.Errorf("duplicate arkade emulator signature")
			}
			arkadeSig = s
		default:
			return fmt.Errorf("unexpected taproot key")
		}
	}
	if hotSig == nil || provSig == nil || arkadeSig == nil || len(in.TaprootScriptSpendSig) != 3 {
		return fmt.Errorf("expected hot, tweaked-provider, and tweaked-arkade signatures")
	}
	if err := verifySchnorrTapSig(ptx, hotSig, wantHot, v.Leaves.Collaborative.Script); err != nil {
		return fmt.Errorf("hot signature: %w", err)
	}
	if err := verifySchnorrTapSig(ptx, provSig, wantProv, v.Leaves.Collaborative.Script); err != nil {
		return fmt.Errorf("provider signature: %w", err)
	}
	if err := verifySchnorrTapSig(ptx, arkadeSig, wantArkade, v.Leaves.Collaborative.Script); err != nil {
		return fmt.Errorf("arkade emulator signature: %w", err)
	}
	return nil
}

func verifySchnorrTapSig(ptx *psbt.Packet, s *psbt.TaprootScriptSpendSig, wantXOnly, leafScript []byte) error {
	if len(s.Signature) != 64 {
		return fmt.Errorf("signature length")
	}
	prev := ptx.Inputs[0].WitnessUtxo
	fetcher := NewPrevFetcher(ptx.UnsignedTx.TxIn[0].PreviousOutPoint, prev)
	digest, err := txscript.CalcTapscriptSignaturehash(
		txscript.NewTxSigHashes(ptx.UnsignedTx, fetcher),
		txscript.SigHashDefault, ptx.UnsignedTx, 0, fetcher, txscript.NewBaseTapLeaf(leafScript),
	)
	if err != nil {
		return err
	}
	sig, err := schnorr.ParseSignature(s.Signature)
	if err != nil {
		return err
	}
	pub, err := schnorr.ParsePubKey(wantXOnly)
	if err != nil {
		return err
	}
	if !sig.Verify(digest, pub) {
		return fmt.Errorf("invalid")
	}
	return nil
}

func writeFinalWitness(ptx *psbt.Packet, leaf *Leaf) error {
	if ptx == nil || leaf == nil || leaf.Closure == nil {
		return fmt.Errorf("missing leaf")
	}
	if len(ptx.Inputs) != 1 {
		return fmt.Errorf("exactly one input required")
	}
	sigs := map[string][]byte{}
	for _, s := range ptx.Inputs[0].TaprootScriptSpendSig {
		sigs[fmt.Sprintf("%x", s.XOnlyPubKey)] = s.Signature
	}
	wit, err := leaf.Closure.Witness(leaf.ControlBlock, sigs)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := psbt.WriteTxWitness(&buf, wit); err != nil {
		return err
	}
	ptx.Inputs[0].FinalScriptWitness = buf.Bytes()
	return nil
}

// ExecuteFinalizedCollaborative runs the standard-script engine against the
// finalized collaborative input and the verified prevout. Callers must
// finalize a clone first.
func ExecuteFinalizedCollaborative(ptx *psbt.Packet, v *Built) error {
	if ptx == nil || v == nil {
		return fmt.Errorf("execute inputs")
	}
	tx, err := ExtractFinalizedTx(ptx)
	if err != nil {
		return err
	}
	prev := ptx.Inputs[0].WitnessUtxo
	if prev == nil {
		return fmt.Errorf("witness utxo required")
	}
	fetcher := NewPrevFetcher(tx.TxIn[0].PreviousOutPoint, prev)
	eng, err := txscript.NewEngine(
		prev.PkScript, tx, 0, txscript.StandardVerifyFlags, nil,
		txscript.NewTxSigHashes(tx, fetcher), prev.Value, fetcher,
	)
	if err != nil {
		return err
	}
	return eng.Execute()
}

// FinalizeOwner builds the Bitcoin witness from the hot+offline owner sigs.
func FinalizeOwner(ptx *psbt.Packet, vault *Built) error {
	return finalizeLeaf(ptx, vault.Leaves.Owner)
}

func finalizeLeaf(ptx *psbt.Packet, leaf *Leaf) error {
	if ptx == nil || ptx.UnsignedTx == nil || leaf == nil {
		return fmt.Errorf("missing leaf")
	}
	if len(ptx.Inputs) != 1 {
		return fmt.Errorf("exactly one input required")
	}
	if len(ptx.Inputs[0].FinalScriptWitness) != 0 || len(ptx.Inputs[0].FinalScriptSig) != 0 {
		return fmt.Errorf("preexisting final script")
	}
	return writeFinalWitness(ptx, leaf)
}

// ExtractFinalizedTx copies the unsigned transaction and attaches the
// finalized input witness. It does not re-sign.
func ExtractFinalizedTx(ptx *psbt.Packet) (*wire.MsgTx, error) {
	if ptx == nil || ptx.UnsignedTx == nil || len(ptx.Inputs) != 1 {
		return nil, fmt.Errorf("finalized psbt")
	}
	if len(ptx.Inputs[0].FinalScriptWitness) == 0 {
		return nil, fmt.Errorf("missing final script witness")
	}
	wit, err := txutils.ReadTxWitness(ptx.Inputs[0].FinalScriptWitness)
	if err != nil {
		return nil, err
	}
	tx := ptx.UnsignedTx.Copy()
	tx.TxIn[0].Witness = wit
	return tx, nil
}

// OwnerSpend builds a hot+offline spend with no emulator packet.
func OwnerSpend(v *Built, prevTx *wire.MsgTx, op wire.OutPoint, dest []byte, destAmt, fee int64, sequence uint32) (*psbt.Packet, error) {
	if v == nil || v.Leaves.Owner == nil {
		return nil, fmt.Errorf("owner leaf required")
	}
	if len(dest) == 0 {
		return nil, fmt.Errorf("destination script required")
	}
	prev, err := checkedPrevout(v, prevTx, op)
	if err != nil {
		return nil, err
	}
	if destAmt < fixture.DustSats || fee < 0 {
		return nil, fmt.Errorf("invalid amount")
	}
	change, err := remainingAfter(prev.Value, destAmt, fee)
	if err != nil {
		return nil, err
	}
	tx := wire.NewMsgTx(2)
	if sequence == 0 {
		sequence = wire.MaxTxInSequenceNum
	}
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: op, Sequence: sequence})
	tx.AddTxOut(&wire.TxOut{Value: destAmt, PkScript: dest})
	switch {
	case change == 0:
		// fully consumed
	case change >= fixture.DustSats && !bytes.Equal(dest, v.PkScript):
		tx.AddTxOut(&wire.TxOut{Value: change, PkScript: v.PkScript})
	default:
		return nil, fmt.Errorf("owner spend does not balance")
	}
	ptx, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		return nil, err
	}
	ptx.Inputs[0].WitnessUtxo = &wire.TxOut{Value: prev.Value, PkScript: prev.PkScript}
	ptx.Inputs[0].SighashType = txscript.SigHashDefault
	ptx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		ControlBlock: v.Leaves.Owner.ControlBlock,
		Script:       v.Leaves.Owner.Script,
		LeafVersion:  txscript.BaseLeafVersion,
	}}
	return ptx, nil
}

// RecoverySpend builds a CSV+offline spend.
func RecoverySpend(v *Built, prevTx *wire.MsgTx, op wire.OutPoint, dest []byte, destAmt, fee int64) (*psbt.Packet, error) {
	if v == nil || v.Leaves.Recovery == nil {
		return nil, fmt.Errorf("recovery leaf required")
	}
	if len(dest) == 0 {
		return nil, fmt.Errorf("destination script required")
	}
	if destAmt < fixture.DustSats || fee < 0 {
		return nil, fmt.Errorf("invalid amount")
	}
	prev, err := checkedPrevout(v, prevTx, op)
	if err != nil {
		return nil, err
	}
	seq, err := arklib.BIP68Sequence(v.Record.CSV)
	if err != nil {
		return nil, err
	}
	left, err := remainingAfter(prev.Value, destAmt, fee)
	if err != nil {
		return nil, err
	}
	if left != 0 {
		return nil, fmt.Errorf("recovery spend must consume the input")
	}
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: op, Sequence: seq})
	tx.AddTxOut(&wire.TxOut{Value: destAmt, PkScript: dest})
	ptx, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		return nil, err
	}
	ptx.Inputs[0].WitnessUtxo = &wire.TxOut{Value: prev.Value, PkScript: prev.PkScript}
	ptx.Inputs[0].SighashType = txscript.SigHashDefault
	ptx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		ControlBlock: v.Leaves.Recovery.ControlBlock,
		Script:       v.Leaves.Recovery.Script,
		LeafVersion:  txscript.BaseLeafVersion,
	}}
	return ptx, nil
}

func checkedPrevout(v *Built, prevTx *wire.MsgTx, op wire.OutPoint) (*wire.TxOut, error) {
	if v == nil {
		return nil, fmt.Errorf("vault required")
	}
	if prevTx == nil {
		return nil, fmt.Errorf("prevout transaction required")
	}
	if prevTx.TxHash() != op.Hash {
		return nil, fmt.Errorf("prevout tx hash mismatch")
	}
	if int(op.Index) >= len(prevTx.TxOut) {
		return nil, fmt.Errorf("prevout index out of range")
	}
	prev := prevTx.TxOut[op.Index]
	if prev == nil {
		return nil, fmt.Errorf("missing prevout")
	}
	if !bytes.Equal(prev.PkScript, v.PkScript) {
		return nil, fmt.Errorf("prevout script is not this vault")
	}
	if err := requireSats(prev.Value, "prevout"); err != nil {
		return nil, err
	}
	return prev, nil
}

func requireSats(v int64, name string) error {
	if v < 0 || v > btcutil.MaxSatoshi {
		return fmt.Errorf("%s outside bitcoin money range", name)
	}
	return nil
}

func subSats(lhs, rhs int64) (int64, error) {
	if rhs < 0 || lhs < rhs {
		return 0, fmt.Errorf("outputs exceed input")
	}
	return lhs - rhs, nil
}

func remainingAfter(input, amount, fee int64) (int64, error) {
	if err := requireSats(input, "input"); err != nil {
		return 0, err
	}
	if err := requireSats(amount, "amount"); err != nil {
		return 0, err
	}
	if err := requireSats(fee, "fee"); err != nil {
		return 0, err
	}
	afterAmount, err := subSats(input, amount)
	if err != nil {
		return 0, err
	}
	return subSats(afterAmount, fee)
}

// RequireVerifiedPrevout loads PrevoutTxField and checks hash, vout and WitnessUtxo.
func RequireVerifiedPrevout(ptx *psbt.Packet) (*wire.MsgTx, error) {
	if ptx == nil || ptx.UnsignedTx == nil || len(ptx.Inputs) != 1 || len(ptx.UnsignedTx.TxIn) != 1 {
		return nil, fmt.Errorf("exactly one input required")
	}
	if ptx.Inputs[0].WitnessUtxo == nil {
		return nil, fmt.Errorf("witness utxo required")
	}
	fields, err := txutils.GetArkPsbtFields(ptx, 0, arkade.PrevoutTxField)
	if err != nil {
		return nil, err
	}
	if len(fields) != 1 {
		return nil, fmt.Errorf("PrevoutTxField required")
	}
	prev := fields[0]
	op := ptx.UnsignedTx.TxIn[0].PreviousOutPoint
	if prev.TxHash() != op.Hash {
		return nil, fmt.Errorf("prevout tx hash mismatch")
	}
	if int(op.Index) >= len(prev.TxOut) {
		return nil, fmt.Errorf("prevout vout out of range")
	}
	want := prev.TxOut[op.Index]
	got := ptx.Inputs[0].WitnessUtxo
	if want == nil || got.Value != want.Value || !bytes.Equal(got.PkScript, want.PkScript) {
		return nil, fmt.Errorf("witness utxo does not match prevout")
	}
	return &prev, nil
}

// HashFromStr is a thin helper for tests and the demo.
func HashFromStr(s string) (*chainhash.Hash, error) {
	return chainhash.NewHashFromStr(s)
}
