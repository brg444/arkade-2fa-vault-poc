package v5

import (
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
)

var padScript = []byte{0x6a}

// Checksig is the v5 tapscript leaf: OP_CHECKSIG for each pub.
func Checksig(pubs ...*btcec.PublicKey) ([]byte, error) {
	return checksig(pubs...)
}

func checksig(pubs ...*btcec.PublicKey) ([]byte, error) {
	script, err := (&arkscript.MultisigClosure{PubKeys: pubs}).Script()
	if err != nil {
		return nil, err
	}
	return script, nil
}

func csvChecksig(blocks uint32, pub *btcec.PublicKey) ([]byte, error) {
	c := &arkscript.CSVMultisigClosure{
		MultisigClosure: arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{pub}},
		Locktime:        arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: blocks},
	}
	return c.Script()
}

func pendingDelay(claimant string) uint32 {
	switch claimant {
	case "hardware":
		return 6
	case "phone":
		return 144
	default:
		return 288
	}
}

func quarantineGuardians(claimant string) (string, string) {
	switch claimant {
	case "phone":
		return "hardware", "recovery"
	case "hardware":
		return "phone", "recovery"
	default:
		return "phone", "hardware"
	}
}

func rolePub(roles map[string]*btcec.PublicKey, name string) (*btcec.PublicKey, error) {
	pub := roles[name]
	if pub == nil {
		return nil, fmt.Errorf("missing %s", name)
	}
	return pub, nil
}

// BuildQuarantine returns the 2-of-2 excluding claimant.
func BuildQuarantine(vaultID, kind, claimant, network string, phone, hardware, recovery *btcec.PublicKey) (addr string, pkScript []byte, err error) {
	internal, err := ContextInternalKey(vaultID, kind, claimant)
	if err != nil {
		return "", nil, err
	}
	roles := map[string]*btcec.PublicKey{"phone": phone, "hardware": hardware, "recovery": recovery}
	a, b := quarantineGuardians(claimant)
	pa, err := rolePub(roles, a)
	if err != nil {
		return "", nil, err
	}
	pb, err := rolePub(roles, b)
	if err != nil {
		return "", nil, err
	}
	script, err := checksig(pa, pb)
	if err != nil {
		return "", nil, err
	}
	return taprootFromScripts(internal, [][]byte{script}, network)
}

// BuildPending returns CSV+claimant, two guardian 3-of-3s, padding.
func BuildPending(vaultID, kind, claimant, network string, phone, hardware, recovery, vaultTweak, arkadeTweak *btcec.PublicKey) (addr string, pkScript []byte, err error) {
	internal, err := ContextInternalKey(vaultID, kind, claimant)
	if err != nil {
		return "", nil, err
	}
	roles := map[string]*btcec.PublicKey{"phone": phone, "hardware": hardware, "recovery": recovery}
	claimantPub, err := rolePub(roles, claimant)
	if err != nil {
		return "", nil, err
	}
	claim, err := csvChecksig(pendingDelay(claimant), claimantPub)
	if err != nil {
		return "", nil, err
	}
	var clawbacks [][]byte
	for _, g := range []string{"phone", "hardware", "recovery"} {
		if g == claimant {
			continue
		}
		gp, err := rolePub(roles, g)
		if err != nil {
			return "", nil, err
		}
		cb, err := checksig(gp, vaultTweak, arkadeTweak)
		if err != nil {
			return "", nil, err
		}
		clawbacks = append(clawbacks, cb)
	}
	scripts := [][]byte{claim}
	scripts = append(scripts, clawbacks...)
	scripts = append(scripts, padScript)
	return taprootFromScripts(internal, scripts, network)
}
