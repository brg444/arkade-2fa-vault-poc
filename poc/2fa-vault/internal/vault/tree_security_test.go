package vault

import (
	"bytes"
	"testing"

	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
)

func TestRecoveryKeyRequiredOnAdminAndRecoveryPaths(t *testing.T) {
	t.Parallel()

	f := newSecurityVaultFixture(t)
	op := f.operational
	sv := f.savings

	if !leafContainsSecurityKey(op.Leaves.Admin, f.recovery.PubKey()) {
		t.Fatal("Operational admin leaf does not require the RecoveryKey")
	}
	if !leafContainsSecurityKey(op.Leaves.Recovery, f.recovery.PubKey()) {
		t.Fatal("Operational recovery leaf does not require the RecoveryKey")
	}
	if !leafContainsSecurityKey(sv.Leaves.Admin, f.recovery.PubKey()) {
		t.Fatal("Savings admin leaf does not require the RecoveryKey")
	}
	if !leafContainsSecurityKey(sv.Leaves.Recovery, f.recovery.PubKey()) {
		t.Fatal("Savings recovery leaf does not require the RecoveryKey")
	}
	if leafContainsSecurityKey(op.Leaves.Routine, f.recovery.PubKey()) {
		t.Fatal("routine leaf unexpectedly contains the RecoveryKey")
	}
	if err := sv.AssertNoRoutineCosigners(f.vaultCosigner.PubKey(), op.TweakedVaultCosigner, f.arkadeCosigner.PubKey(), op.TweakedArkadeCosigner); err != nil {
		t.Fatal(err)
	}
	if sv.ContainsKey(f.vaultCosigner.PubKey()) || sv.ContainsKey(op.TweakedVaultCosigner) ||
		sv.ContainsKey(f.arkadeCosigner.PubKey()) || sv.ContainsKey(op.TweakedArkadeCosigner) {
		t.Fatal("Savings contains a provider key")
	}
	if sv.Leaves.Routine != nil {
		t.Fatal("Savings must not have a provider routine path")
	}
}

func TestOperationalAndSavingsVaultKeyContainment(t *testing.T) {
	t.Parallel()

	f := newSecurityVaultFixture(t)
	op := f.operational
	savings := f.savings

	if op.Leaves.Routine == nil {
		t.Fatal("Operational vault is missing routine leaf")
	}
	if !op.ContainsTweakedVaultCosigner() {
		t.Fatal("Operational vault does not contain its tweaked Provider key")
	}
	if !op.ContainsTweakedArkadeCosigner() {
		t.Fatal("Operational vault does not contain its tweaked Arkade Emulator key")
	}
	if op.ContainsKey(f.vaultCosigner.PubKey()) || op.ContainsKey(f.arkadeCosigner.PubKey()) {
		t.Fatal("Operational vault contains an untweaked collaborator base key")
	}
	if !leafContainsSecurityKey(op.Leaves.Routine, f.phoneRoutine.PubKey()) ||
		!leafContainsSecurityKey(op.Leaves.Routine, op.TweakedVaultCosigner) ||
		!leafContainsSecurityKey(op.Leaves.Routine, op.TweakedArkadeCosigner) {
		t.Fatal("routine leaf must contain exactly hot and both tweaked collaborators")
	}
	if leafContainsSecurityKey(op.Leaves.Admin, op.TweakedVaultCosigner) ||
		leafContainsSecurityKey(op.Leaves.Recovery, op.TweakedVaultCosigner) ||
		leafContainsSecurityKey(op.Leaves.Admin, op.TweakedArkadeCosigner) ||
		leafContainsSecurityKey(op.Leaves.Recovery, op.TweakedArkadeCosigner) {
		t.Fatal("collaborator key leaked into an owner-controlled Operational path")
	}

	if savings.Leaves.Routine != nil {
		t.Fatal("Savings vault unexpectedly has a routine leaf")
	}
	if savings.ContainsKey(f.vaultCosigner.PubKey()) || savings.ContainsKey(op.TweakedVaultCosigner) ||
		savings.ContainsKey(f.arkadeCosigner.PubKey()) || savings.ContainsKey(op.TweakedArkadeCosigner) {
		t.Fatal("Savings vault contains routine signing authority")
	}
	if bytes.Equal(op.PkScript, savings.PkScript) || op.Address == savings.Address {
		t.Fatal("Operational and Savings vaults unexpectedly derived the same output")
	}
}

func TestVaultClosuresHaveExpectedKeysAndDelays(t *testing.T) {
	t.Parallel()

	f := newSecurityVaultFixture(t)
	op := f.operational
	savings := f.savings

	assertSecurityMultisigKeys(t, op.Leaves.Routine, f.phoneRoutine.PubKey(), op.TweakedVaultCosigner, op.TweakedArkadeCosigner)
	assertSecurityMultisigKeys(t, op.Leaves.Admin, f.externalOwner.PubKey(), f.recovery.PubKey())
	assertSecurityCSVKeyAndDelay(t, op.Leaves.Recovery, f.recovery.PubKey(), op.Record.CSV.Value)
	assertSecurityMultisigKeys(t, savings.Leaves.Admin, f.externalOwner.PubKey(), f.recovery.PubKey())
	assertSecurityCSVKeyAndDelay(t, savings.Leaves.Recovery, f.recovery.PubKey(), savings.Record.CSV.Value)
	if savings.Record.CSV.Value <= op.Record.CSV.Value {
		t.Fatalf("Savings delay %d must exceed Operational delay %d", savings.Record.CSV.Value, op.Record.CSV.Value)
	}
}

func TestEveryVaultLeafCommitsToItsCanonicalOutput(t *testing.T) {
	t.Parallel()

	f := newSecurityVaultFixture(t)
	for _, built := range []*Built{f.operational, f.savings} {
		for _, leaf := range []*Leaf{built.Leaves.Routine, built.Leaves.Admin, built.Leaves.Recovery} {
			if leaf == nil {
				continue
			}
			psbtLeaf := &psbt.TaprootTapLeafScript{
				ControlBlock: leaf.ControlBlock,
				Script:       leaf.Script,
				LeafVersion:  txscript.BaseLeafVersion,
			}
			if err := arkade.VerifyTaprootLeafCommitment(built.PkScript, psbtLeaf); err != nil {
				t.Fatalf("%s leaf does not commit to %s: %v", leaf.Name, built.Address, err)
			}
		}
	}
}

func TestEveryVaultPathUsesTheDocumentedNUMSInternalKey(t *testing.T) {
	t.Parallel()

	f := newSecurityVaultFixture(t)
	want := schnorr.SerializePubKey(arkscript.UnspendableKey())
	for _, built := range []*Built{f.operational, f.savings} {
		for _, leaf := range []*Leaf{built.Leaves.Routine, built.Leaves.Admin, built.Leaves.Recovery} {
			if leaf == nil {
				continue
			}
			control, err := txscript.ParseControlBlock(leaf.ControlBlock)
			if err != nil {
				t.Fatalf("%s control block: %v", leaf.Name, err)
			}
			if !bytes.Equal(schnorr.SerializePubKey(control.InternalKey), want) {
				t.Fatalf("%s path does not use the documented NUMS internal key", leaf.Name)
			}
		}
	}
}

func TestVaultTreeHasNoUndocumentedScriptPaths(t *testing.T) {
	t.Parallel()

	f := newSecurityVaultFixture(t)
	if got := len(f.operational.Tree.Closures); got != 3 {
		t.Fatalf("Operational closure count = %d, want routine + admin + recovery", got)
	}
	if got := len(f.savings.Tree.Closures); got != 2 {
		t.Fatalf("Savings closure count = %d, want admin + recovery", got)
	}
}

func leafContainsSecurityKey(leaf *Leaf, pub *btcec.PublicKey) bool {
	if leaf == nil || pub == nil {
		return false
	}
	return bytes.Contains(leaf.Script, schnorr.SerializePubKey(pub))
}

func assertSecurityMultisigKeys(t *testing.T, leaf *Leaf, want ...*btcec.PublicKey) {
	t.Helper()
	closure, ok := leaf.Closure.(*arkscript.MultisigClosure)
	if !ok {
		t.Fatalf("%s closure = %T, want MultisigClosure", leaf.Name, leaf.Closure)
	}
	if len(closure.PubKeys) != len(want) {
		t.Fatalf("%s key count = %d, want %d", leaf.Name, len(closure.PubKeys), len(want))
	}
	for i := range want {
		if !bytes.Equal(schnorr.SerializePubKey(closure.PubKeys[i]), schnorr.SerializePubKey(want[i])) {
			t.Fatalf("%s key %d mismatch", leaf.Name, i)
		}
	}
}

func assertSecurityCSVKeyAndDelay(t *testing.T, leaf *Leaf, want *btcec.PublicKey, delay uint32) {
	t.Helper()
	closure, ok := leaf.Closure.(*arkscript.CSVMultisigClosure)
	if !ok {
		t.Fatalf("%s closure = %T, want CSVMultisigClosure", leaf.Name, leaf.Closure)
	}
	if len(closure.PubKeys) != 1 ||
		!bytes.Equal(schnorr.SerializePubKey(closure.PubKeys[0]), schnorr.SerializePubKey(want)) {
		t.Fatalf("%s does not contain only the RecoveryKey", leaf.Name)
	}
	if closure.Locktime.Value != delay {
		t.Fatalf("%s delay = %d, want %d", leaf.Name, closure.Locktime.Value, delay)
	}
}
