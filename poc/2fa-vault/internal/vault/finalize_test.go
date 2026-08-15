package vault

import (
	"strings"
	"testing"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/emulator/poc/2fa-vault/internal/webauthn"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func TestFinalizeCollaborativeFailClosed(t *testing.T) {
	t.Parallel()
	f := newSecurityVaultFixture(t)
	ptx := signedCollaborative(t, f)

	if err := FinalizeCollaborative(nil, f.operational); err == nil {
		t.Fatal("nil packet accepted")
	}
	if err := FinalizeCollaborative(ptx, nil); err == nil {
		t.Fatal("nil vault accepted")
	}

	pre := clonePSBT(t, ptx)
	pre.Inputs[0].FinalScriptWitness = []byte{0x01, 0x00}
	if err := FinalizeCollaborative(pre, f.operational); err == nil {
		t.Fatal("preexisting final witness accepted")
	}
	preSig := clonePSBT(t, ptx)
	preSig.Inputs[0].FinalScriptSig = []byte{txscript.OP_TRUE}
	if err := FinalizeCollaborative(preSig, f.operational); err == nil {
		t.Fatal("preexisting final scriptsig accepted")
	}

	dup := clonePSBT(t, ptx)
	dup.Inputs[0].TaprootScriptSpendSig = append(dup.Inputs[0].TaprootScriptSpendSig, dup.Inputs[0].TaprootScriptSpendSig[0])
	if err := FinalizeCollaborative(dup, f.operational); err == nil {
		t.Fatal("duplicate signature accepted")
	}

	wrongLeaf := clonePSBT(t, ptx)
	wrongLeaf.Inputs[0].TaprootLeafScript[0].Script = append([]byte(nil), f.operational.Leaves.Owner.Script...)
	if err := FinalizeCollaborative(wrongLeaf, f.operational); err == nil {
		t.Fatal("wrong leaf accepted")
	}

	wrongHash := clonePSBT(t, ptx)
	wrongHash.Inputs[0].TaprootScriptSpendSig[0].SigHash = txscript.SigHashAll
	if err := FinalizeCollaborative(wrongHash, f.operational); err == nil {
		t.Fatal("wrong sighash accepted")
	}

	badSig := clonePSBT(t, ptx)
	badSig.Inputs[0].TaprootScriptSpendSig[0].Signature = make([]byte, 64)
	if err := FinalizeCollaborative(badSig, f.operational); err == nil {
		t.Fatal("invalid signature accepted")
	}

	if err := FinalizeCollaborative(ptx, f.operational); err != nil {
		t.Fatalf("valid collaborative finalize: %v", err)
	}
	if err := ExecuteFinalizedCollaborative(ptx, f.operational); err != nil {
		t.Fatalf("local engine: %v", err)
	}
}

func signedCollaborative(t *testing.T, f *securityVaultFixture) *psbt.Packet {
	t.Helper()
	spend, err := BuildCollaborativeSpend(f.collaborativeParams())
	if err != nil {
		t.Fatal(err)
	}
	direct, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := webauthn.SignDigestLowS(direct, spend.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err := SetPacketWitness(spend.Packet.UnsignedTx, wire.TxWitness{sig}); err != nil {
		t.Fatal(err)
	}
	hotSig, err := SignLeaf(spend.Packet.UnsignedTx, spend.Packet.Inputs[0].WitnessUtxo, f.operational.Leaves.Collaborative.Script, f.hot)
	if err != nil {
		t.Fatal(err)
	}
	AddPartialSig(spend.Packet, f.hot.PubKey(), f.operational.Leaves.Collaborative.Hash, hotSig)
	tweak := arkade.ArkadeScriptHash(f.operational.Record.AuthScript)
	prov := arkade.ComputeArkadeScriptPrivateKey(f.provider, tweak)
	provSig, err := SignLeaf(spend.Packet.UnsignedTx, spend.Packet.Inputs[0].WitnessUtxo, f.operational.Leaves.Collaborative.Script, prov)
	if err != nil {
		t.Fatal(err)
	}
	AddPartialSig(spend.Packet, prov.PubKey(), f.operational.Leaves.Collaborative.Hash, provSig)
	return spend.Packet
}

func clonePSBT(t *testing.T, ptx *psbt.Packet) *psbt.Packet {
	t.Helper()
	raw, err := ptx.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	out, err := psbt.NewFromRawBytes(strings.NewReader(raw), true)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
