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

func TestOfflineSignerRequiredOnOwnerRecoveryAndAbsentFromSavings(t *testing.T) {
	t.Parallel()

	f := newSecurityVaultFixture(t)
	op := f.operational
	sv := f.savings

	if !leafContainsSecurityKey(op.Leaves.Owner, f.offline.PubKey()) {
		t.Fatal("Operational owner leaf does not require the offline key")
	}
	if !leafContainsSecurityKey(op.Leaves.Recovery, f.offline.PubKey()) {
		t.Fatal("Operational recovery leaf does not require the offline key")
	}
	if !leafContainsSecurityKey(sv.Leaves.Owner, f.offline.PubKey()) {
		t.Fatal("Savings owner leaf does not require the offline key")
	}
	if !leafContainsSecurityKey(sv.Leaves.Recovery, f.offline.PubKey()) {
		t.Fatal("Savings recovery leaf does not require the offline key")
	}
	if leafContainsSecurityKey(op.Leaves.Collaborative, f.offline.PubKey()) {
		t.Fatal("collaborative leaf unexpectedly contains the offline key")
	}
	if err := sv.AssertNoProvider(f.provider.PubKey(), op.TweakedProvider); err != nil {
		t.Fatal(err)
	}
	if sv.ContainsProvider(f.provider.PubKey()) || sv.ContainsProvider(op.TweakedProvider) {
		t.Fatal("Savings contains a provider key")
	}
	if sv.Leaves.Collaborative != nil {
		t.Fatal("Savings must not have a provider collaborative path")
	}
}

func TestOperationalAndSavingsVaultKeyContainment(t *testing.T) {
	t.Parallel()

	f := newSecurityVaultFixture(t)
	op := f.operational
	savings := f.savings

	if op.Leaves.Collaborative == nil {
		t.Fatal("Operational vault is missing collaborative leaf")
	}
	if !op.ContainsTweakedProvider() {
		t.Fatal("Operational vault does not contain its tweaked Provider key")
	}
	if op.ContainsProvider(f.provider.PubKey()) {
		t.Fatal("Operational vault contains the untweaked Provider base key")
	}
	if !leafContainsSecurityKey(op.Leaves.Collaborative, f.hot.PubKey()) ||
		!leafContainsSecurityKey(op.Leaves.Collaborative, op.TweakedProvider) {
		t.Fatal("collaborative leaf must contain exactly the hot and tweaked Provider authorities")
	}
	if leafContainsSecurityKey(op.Leaves.Owner, op.TweakedProvider) ||
		leafContainsSecurityKey(op.Leaves.Recovery, op.TweakedProvider) {
		t.Fatal("Provider key leaked into an owner-controlled Operational path")
	}

	if savings.Leaves.Collaborative != nil {
		t.Fatal("Savings vault unexpectedly has a collaborative leaf")
	}
	if savings.ContainsProvider(f.provider.PubKey()) || savings.ContainsProvider(op.TweakedProvider) {
		t.Fatal("Savings vault contains Provider signing authority")
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

	assertSecurityMultisigKeys(t, op.Leaves.Collaborative, f.hot.PubKey(), op.TweakedProvider)
	assertSecurityMultisigKeys(t, op.Leaves.Owner, f.hot.PubKey(), f.offline.PubKey())
	assertSecurityCSVKeyAndDelay(t, op.Leaves.Recovery, f.offline.PubKey(), op.Record.CSV.Value)
	assertSecurityMultisigKeys(t, savings.Leaves.Owner, f.hot.PubKey(), f.offline.PubKey())
	assertSecurityCSVKeyAndDelay(t, savings.Leaves.Recovery, f.offline.PubKey(), savings.Record.CSV.Value)
	if savings.Record.CSV.Value <= op.Record.CSV.Value {
		t.Fatalf("Savings delay %d must exceed Operational delay %d", savings.Record.CSV.Value, op.Record.CSV.Value)
	}
}

func TestEveryVaultLeafCommitsToItsCanonicalOutput(t *testing.T) {
	t.Parallel()

	f := newSecurityVaultFixture(t)
	for _, built := range []*Built{f.operational, f.savings} {
		for _, leaf := range []*Leaf{built.Leaves.Collaborative, built.Leaves.Owner, built.Leaves.Recovery} {
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
		for _, leaf := range []*Leaf{built.Leaves.Collaborative, built.Leaves.Owner, built.Leaves.Recovery} {
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
		t.Fatalf("Operational closure count = %d, want collaborative + owner + recovery", got)
	}
	if got := len(f.savings.Tree.Closures); got != 2 {
		t.Fatalf("Savings closure count = %d, want owner + recovery", got)
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
		t.Fatalf("%s does not contain only the offline key", leaf.Name)
	}
	if closure.Locktime.Value != delay {
		t.Fatalf("%s delay = %d, want %d", leaf.Name, closure.Locktime.Value, delay)
	}
}
