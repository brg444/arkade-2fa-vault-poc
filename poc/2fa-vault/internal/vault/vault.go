package vault

import (
	"bytes"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/emulator/poc/2fa-vault/fixture"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

// Kind identifies which vault tree is being built.
type Kind int

const (
	Operational Kind = iota
	Savings
)

// Record is the single canonical policy used to derive every leaf, address
// and descriptor for one vault.
type Record struct {
	Kind           Kind
	Hot            *btcec.PublicKey
	Offline        *btcec.PublicKey
	ProviderBase   *btcec.PublicKey
	DirectP256     []byte
	CSV            arklib.RelativeLocktime
	AuthScript     []byte
	AuthScriptHash []byte
	Network        string
}

// Built is a fully derived vault tree.
type Built struct {
	Record          Record
	Tree            *arkscript.TapscriptsVtxoScript
	TapKey          *btcec.PublicKey
	PkScript        []byte
	Address         string
	Leaves          Leaves
	TweakedProvider *btcec.PublicKey
}

// Leaves holds decoded leaf scripts and control blocks.
type Leaves struct {
	Collaborative *Leaf // Operational only
	Owner         *Leaf
	Recovery      *Leaf
}

// Leaf is one tapscript path.
type Leaf struct {
	Name         string
	Closure      arkscript.Closure
	Script       []byte
	ControlBlock []byte
	Hash         []byte
}

// NewOperational builds the Operational tree: hot+provider, hot+offline, CSV+offline.
func NewOperational(hot, offline, providerBase *btcec.PublicKey, directP256 []byte) (*Built, error) {
	auth, err := AuthorizationScript(directP256)
	if err != nil {
		return nil, err
	}
	rec := Record{
		Kind:           Operational,
		Hot:            hot,
		Offline:        offline,
		ProviderBase:   providerBase,
		DirectP256:     append([]byte(nil), directP256...),
		CSV:            fixture.OperationalCSV(),
		AuthScript:     auth,
		AuthScriptHash: arkade.ArkadeScriptHash(auth),
		Network:        fixture.Network,
	}
	return NewFromRecord(rec)
}

// NewSavings builds the Savings tree: hot+offline, long CSV+offline. No provider.
// forbidden is the Operational provider base key and/or tweaked provider key
// that must not appear in any Savings leaf.
func NewSavings(hot, offline *btcec.PublicKey, forbidden ...*btcec.PublicKey) (*Built, error) {
	rec := Record{
		Kind:    Savings,
		Hot:     hot,
		Offline: offline,
		CSV:     fixture.SavingsCSV(),
		Network: fixture.Network,
	}
	b, err := NewFromRecord(rec)
	if err != nil {
		return nil, err
	}
	if err := b.AssertNoProvider(forbidden...); err != nil {
		return nil, err
	}
	return b, nil
}

// NewFromRecord rebuilds a vault solely from a persisted record. Callers must
// not substitute the current process's GetInfo/config keys.
//
// Operational trees treat DirectP256 as canonical: AuthorizationScript and
// ArkadeScriptHash are always derived from it. A nonempty supplied script or
// hash that differs from the derived values is rejected; empty fields are
// filled with the derived values.
func NewFromRecord(rec Record) (*Built, error) {
	if rec.Hot == nil || rec.Offline == nil {
		return nil, fmt.Errorf("hot and offline keys required")
	}
	if rec.CSV.Value == 0 {
		return nil, fmt.Errorf("csv required")
	}
	if rec.Network == "" {
		rec.Network = fixture.Network
	}
	switch rec.Kind {
	case Operational:
		if rec.ProviderBase == nil {
			return nil, fmt.Errorf("provider base required")
		}
		auth, err := AuthorizationScript(rec.DirectP256)
		if err != nil {
			return nil, err
		}
		wantHash := arkade.ArkadeScriptHash(auth)
		if len(rec.AuthScript) > 0 && !bytes.Equal(rec.AuthScript, auth) {
			return nil, fmt.Errorf("auth script does not match DirectP256")
		}
		if len(rec.AuthScriptHash) > 0 && !bytes.Equal(rec.AuthScriptHash, wantHash) {
			return nil, fmt.Errorf("auth script hash does not match DirectP256")
		}
		rec.AuthScript = append([]byte(nil), auth...)
		rec.AuthScriptHash = append([]byte(nil), wantHash...)
	case Savings:
	default:
		return nil, fmt.Errorf("invalid vault kind %d", rec.Kind)
	}
	return build(rec)
}

func build(rec Record) (*Built, error) {
	params, err := networkParams(rec.Network)
	if err != nil {
		return nil, err
	}
	owner := &arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{rec.Hot, rec.Offline}}
	recovery := &arkscript.CSVMultisigClosure{
		MultisigClosure: arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{rec.Offline}},
		Locktime:        rec.CSV,
	}

	var closures []arkscript.Closure
	var tweaked *btcec.PublicKey
	switch rec.Kind {
	case Operational:
		tweaked = arkade.ComputeArkadeScriptPublicKey(rec.ProviderBase, rec.AuthScriptHash)
		collab := &arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{rec.Hot, tweaked}}
		closures = []arkscript.Closure{collab, owner, recovery}
	case Savings:
		closures = []arkscript.Closure{owner, recovery}
	default:
		return nil, fmt.Errorf("invalid vault kind %d", rec.Kind)
	}

	tree := &arkscript.TapscriptsVtxoScript{Closures: closures}
	tapKey, tapTree, err := tree.TapTree()
	if err != nil {
		return nil, err
	}
	pkScript, err := arkscript.P2TRScript(tapKey)
	if err != nil {
		return nil, err
	}
	addr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(tapKey), params)
	if err != nil {
		return nil, err
	}

	leafOf := func(name string, c arkscript.Closure) (*Leaf, error) {
		script, err := c.Script()
		if err != nil {
			return nil, err
		}
		proof, err := tapTree.GetTaprootMerkleProof(txscript.NewBaseTapLeaf(script).TapHash())
		if err != nil {
			return nil, err
		}
		h := txscript.NewBaseTapLeaf(script).TapHash()
		return &Leaf{
			Name:         name,
			Closure:      c,
			Script:       script,
			ControlBlock: proof.ControlBlock,
			Hash:         h[:],
		}, nil
	}

	var leaves Leaves
	switch rec.Kind {
	case Operational:
		leaves.Collaborative, err = leafOf("collaborative", closures[0])
		if err != nil {
			return nil, err
		}
		leaves.Owner, err = leafOf("owner", closures[1])
		if err != nil {
			return nil, err
		}
		leaves.Recovery, err = leafOf("recovery", closures[2])
		if err != nil {
			return nil, err
		}
	case Savings:
		leaves.Owner, err = leafOf("owner", closures[0])
		if err != nil {
			return nil, err
		}
		leaves.Recovery, err = leafOf("recovery", closures[1])
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("invalid vault kind %d", rec.Kind)
	}

	return &Built{
		Record:          rec,
		Tree:            tree,
		TapKey:          tapKey,
		PkScript:        pkScript,
		Address:         addr.EncodeAddress(),
		Leaves:          leaves,
		TweakedProvider: tweaked,
	}, nil
}

// AssertNoProvider fails if any forbidden key appears in a serialized leaf
// script or a decoded closure. Callers must pass the real Operational
// provider base and tweaked keys as expected inputs; a nil list proves
// nothing, and Built.TweakedProvider is not itself proof of containment.
func (b *Built) AssertNoProvider(forbidden ...*btcec.PublicKey) error {
	if len(forbidden) == 0 {
		return fmt.Errorf("provider exclusion requires at least one key to check")
	}
	for _, pub := range forbidden {
		if pub == nil {
			return fmt.Errorf("provider exclusion key must not be nil")
		}
		if b.ContainsProvider(pub) {
			return fmt.Errorf("provider key present in vault leaf")
		}
	}
	return nil
}

// ContainsProvider reports whether any serialized leaf script or decoded
// closure key matches pub. The TweakedProvider field is ignored.
func (b *Built) ContainsProvider(pub *btcec.PublicKey) bool {
	if b == nil || pub == nil {
		return false
	}
	want := schnorr.SerializePubKey(pub)
	for _, leaf := range []*Leaf{b.Leaves.Collaborative, b.Leaves.Owner, b.Leaves.Recovery} {
		if leafContainsKey(leaf, want) {
			return true
		}
	}
	if b.Tree != nil {
		for _, c := range b.Tree.Closures {
			if closureContainsKey(c, want) {
				return true
			}
		}
	}
	return false
}

// ContainsTweakedProvider reports whether the expected TweakedProvider key
// actually appears in a leaf. A populated TweakedProvider field is not enough.
func (b *Built) ContainsTweakedProvider() bool {
	if b == nil {
		return false
	}
	return b.ContainsProvider(b.TweakedProvider)
}

func leafContainsKey(leaf *Leaf, want []byte) bool {
	if leaf == nil || len(want) == 0 {
		return false
	}
	if bytes.Contains(leaf.Script, want) {
		return true
	}
	if decoded, err := arkscript.DecodeClosure(leaf.Script); err == nil && closureContainsKey(decoded, want) {
		return true
	}
	return closureContainsKey(leaf.Closure, want)
}

func closureContainsKey(c arkscript.Closure, want []byte) bool {
	if c == nil || len(want) == 0 {
		return false
	}
	if script, err := c.Script(); err == nil && bytes.Contains(script, want) {
		return true
	}
	for _, pub := range closurePubKeys(c) {
		if pub != nil && bytes.Equal(schnorr.SerializePubKey(pub), want) {
			return true
		}
	}
	return false
}

func closurePubKeys(c arkscript.Closure) []*btcec.PublicKey {
	switch t := c.(type) {
	case *arkscript.MultisigClosure:
		return t.PubKeys
	case *arkscript.CSVMultisigClosure:
		return t.PubKeys
	case *arkscript.CLTVMultisigClosure:
		return t.PubKeys
	case *arkscript.ConditionMultisigClosure:
		return t.PubKeys
	case *arkscript.ConditionCSVMultisigClosure:
		return t.PubKeys
	default:
		return nil
	}
}

func networkParams(name string) (*chaincfg.Params, error) {
	switch name {
	case "", fixture.Network, chaincfg.RegressionNetParams.Name:
		return &chaincfg.RegressionNetParams, nil
	default:
		return nil, fmt.Errorf("unsupported network %q", name)
	}
}
