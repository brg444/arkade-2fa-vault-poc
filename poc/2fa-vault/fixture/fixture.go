// Package fixture pins the single-provider, single-policy POC configuration.
package fixture

import (
	"net/url"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
)

const (
	VaultID = "operational-vault-v1"

	RPID   = "localhost"
	Origin = "http://localhost:8787"

	// OperationalCSVBlocks is short so recovery tests can mine past it.
	OperationalCSVBlocks uint32 = 6
	// SavingsCSVBlocks is the longer owner-only recovery delay.
	SavingsCSVBlocks uint32 = 144

	TxRecipientCapSats  int64 = 50_000
	PeriodAllowanceSats int64 = 100_000
	// Absolute and feerate ceilings are independent: 50 sat/vB on a
	// typical ~273–516 vB collaborative template exceeds 5_000 sat, so
	// that pair is unreachable as two separate checks. 10 sat/vB keeps
	// the first rate-only violation under the absolute cap.
	AbsoluteFeeCeiling    int64 = 5_000
	FeerateCeilingSatPerV int64 = 10
	DustSats              int64 = 330

	// PreCore30DatacarrierBytes is Bitcoin Core's default -datacarriersize
	// before v30: an 83-byte scriptPubKey (OP_RETURN + push + 80-byte payload).
	// Core 30 defaults to 100_000, which is usually not the limiting factor.
	PreCore30DatacarrierBytes = 83
	Core30DatacarrierBytes    = 100_000

	PRFSalt            = "arkade-2fa-vault/prf/v1"
	HKDFInfo           = "arkade-2fa-vault/kek/v1"
	DirectP256HKDFInfo = "arkade-2fa-vault/direct-p256/v1"
	HKDFHashName       = "SHA-256"
	// OfflinePubHex is a known-valid compressed secp256k1 point (the generator).
	// Compose uses it as the opaque VAULT_OFFLINE_PUB fixture. The runnable
	// provider never holds the corresponding private scalar.
	OfflinePubHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

	HTTPAddr = "localhost:8787"

	// TemplateVersion / PolicyVersion / Network are persisted at enrollment.
	// A restart with different values must refuse to rebuild the trees.
	TemplateVersion = "2fa-vault-direct-p256-v1"
	PolicyVersion   = "tx50k-day100k-fee5k-feerate10-v1"
	Network         = "regtest"
)

func OperationalCSV() arklib.RelativeLocktime {
	return arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: OperationalCSVBlocks}
}

func SavingsCSV() arklib.RelativeLocktime {
	return arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: SavingsCSVBlocks}
}

func OriginURL() *url.URL {
	u, err := url.Parse(Origin)
	if err != nil {
		panic(err)
	}
	return u
}
