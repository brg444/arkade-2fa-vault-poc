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
	Kind                Kind
	Hot                 *btcec.PublicKey
	Offline             *btcec.PublicKey
	ProviderBase        *btcec.PublicKey
	ArkadeBase          *btcec.PublicKey
	DirectP256          []byte
	CSV                 arklib.RelativeLocktime
	AuthorizationPolicy AuthorizationPolicy
	AuthScript          []byte
	AuthScriptHash      []byte
	Network             string
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
	TweakedArkade   *btcec.PublicKey
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

// OperationalKeys are the independent key roles committed by one Operational
// descriptor. DirectP256 gates both tweaked signers through the shared Arkade
// authorization script; it is not itself a tapscript secp256k1 signer.
type OperationalKeys struct {
	Hot          *btcec.PublicKey
	Offline      *btcec.PublicKey
	ProviderBase *btcec.PublicKey
	ArkadeBase   *btcec.PublicKey
	DirectP256   []byte
}

// NewOperational builds the Operational tree: hot+both independently tweaked
// cosigners, hot+offline, and CSV+offline.
func NewOperational(keys OperationalKeys) (*Built, error) {
	return NewOperationalForNetwork(keys, fixture.Network)
}

// NewOperationalForNetwork builds the same code-pinned Operational template
// using the address encoding of an explicitly supported deployment network.
func NewOperationalForNetwork(keys OperationalKeys, network string) (*Built, error) {
	return NewOperationalWithPolicy(keys, network, fixture.OperationalCSV(), fixtureAuthorizationPolicy())
}

// NewOperationalWithPolicy makes the deployment CSV delay and every
// transaction-local script limit explicit.
func NewOperationalWithPolicy(keys OperationalKeys, network string, csv arklib.RelativeLocktime, policy AuthorizationPolicy) (*Built, error) {
	auth, err := AuthorizationScript(keys.DirectP256, policy)
	if err != nil {
		return nil, err
	}
	rec := Record{
		Kind:                Operational,
		Hot:                 keys.Hot,
		Offline:             keys.Offline,
		ProviderBase:        keys.ProviderBase,
		ArkadeBase:          keys.ArkadeBase,
		DirectP256:          append([]byte(nil), keys.DirectP256...),
		CSV:                 csv,
		AuthorizationPolicy: policy,
		AuthScript:          auth,
		AuthScriptHash:      arkade.ArkadeScriptHash(auth),
		Network:             network,
	}
	return NewFromRecord(rec)
}

func fixtureAuthorizationPolicy() AuthorizationPolicy {
	return AuthorizationPolicy{
		RecipientDustSats:      fixture.DustSats,
		RecipientCapSats:       fixture.TxRecipientCapSats,
		AbsoluteFeeCeilingSats: fixture.AbsoluteFeeCeiling,
		FeerateCeilingSatPerV:  fixture.FeerateCeilingSatPerV,
	}
}

// NewSavings builds the Savings tree: hot+offline, long CSV+offline. Neither
// collaborative cosigner appears. forbidden contains the private Provider and
// public Arkade base/tweaked identities that must not appear in any Savings
// leaf.
func NewSavings(hot, offline *btcec.PublicKey, forbidden ...*btcec.PublicKey) (*Built, error) {
	return NewSavingsForNetwork(hot, offline, fixture.Network, forbidden...)
}

// NewSavingsForNetwork builds the owner-only Savings template for network.
func NewSavingsForNetwork(hot, offline *btcec.PublicKey, network string, forbidden ...*btcec.PublicKey) (*Built, error) {
	return NewSavingsWithPolicy(hot, offline, network, fixture.SavingsCSV(), forbidden...)
}

// NewSavingsWithPolicy makes the deployment CSV delay explicit.
func NewSavingsWithPolicy(hot, offline *btcec.PublicKey, network string, csv arklib.RelativeLocktime, forbidden ...*btcec.PublicKey) (*Built, error) {
	rec := Record{
		Kind:    Savings,
		Hot:     hot,
		Offline: offline,
		CSV:     csv,
		Network: network,
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
	if err := requireIndependentXOnly(rec.Hot, rec.Offline); err != nil {
		return nil, err
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
		if rec.ArkadeBase == nil {
			return nil, fmt.Errorf("arkade emulator base required")
		}
		if err := requireIndependentXOnly(rec.ProviderBase, rec.ArkadeBase, rec.Hot, rec.Offline); err != nil {
			return nil, err
		}
		auth, err := AuthorizationScript(rec.DirectP256, rec.AuthorizationPolicy)
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
	var tweakedProvider, tweakedArkade *btcec.PublicKey
	switch rec.Kind {
	case Operational:
		tweakedProvider = arkade.ComputeArkadeScriptPublicKey(rec.ProviderBase, rec.AuthScriptHash)
		tweakedArkade = arkade.ComputeArkadeScriptPublicKey(rec.ArkadeBase, rec.AuthScriptHash)
		if err := requireIndependentXOnly(
			rec.Hot, rec.Offline, rec.ProviderBase, rec.ArkadeBase,
			tweakedProvider, tweakedArkade,
		); err != nil {
			return nil, err
		}
		collab := &arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{rec.Hot, tweakedProvider, tweakedArkade}}
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
		TweakedProvider: tweakedProvider,
		TweakedArkade:   tweakedArkade,
	}, nil
}

// requireIndependentXOnly compares the identities Bitcoin Taproot actually
// commits to. Opposite compressed-key parities are the same x-only role and
// must not collapse any pair, including provider base versus tweaked provider.
func requireIndependentXOnly(keys ...*btcec.PublicKey) error {
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if sameXOnlyKey(keys[i], keys[j]) {
				return fmt.Errorf("secp256k1 key roles must be independent by x-only identity")
			}
		}
	}
	return nil
}

func sameXOnlyKey(a, b *btcec.PublicKey) bool {
	return a != nil && b != nil && bytes.Equal(schnorr.SerializePubKey(a), schnorr.SerializePubKey(b))
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

// ContainsTweakedArkade reports whether the expected public Arkade
// cosigner's tweaked key actually appears in a leaf.
func (b *Built) ContainsTweakedArkade() bool {
	if b == nil {
		return false
	}
	return b.ContainsProvider(b.TweakedArkade)
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
	case "mutinynet":
		// Use ark-lib's pinned custom challenge/block interval rather than the
		// generic signet params. Address prefixes remain standard signet/testnet.
		return &arklib.MutinyNetSigNetParams, nil
	default:
		return nil, fmt.Errorf("unsupported network %q", name)
	}
}
