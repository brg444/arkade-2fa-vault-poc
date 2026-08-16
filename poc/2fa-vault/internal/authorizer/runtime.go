// Package authorizer assembles the Mutinynet software signing boundary.
// This process is the sole owner of both the provider private key and the
// authoritative issuance ledger. It exposes Service policy operations, never
// the policy-agnostic LocalSigner primitive.
package authorizer

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/arkade-os/emulator/poc/2fa-vault/fixture"
	"github.com/arkade-os/emulator/poc/2fa-vault/internal/deployment"
	"github.com/arkade-os/emulator/poc/2fa-vault/internal/policy"
	"github.com/arkade-os/emulator/poc/2fa-vault/internal/provider"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Config contains only deployment inputs for the protected authorizer. The
// provider key and first-enrollment token are file-backed secrets; neither may
// be supplied through environment text or a network signer.
type Config struct {
	Deployment          deployment.Config
	DatabasePath        string
	ProviderKeyFile     string
	OfflinePubHex       string
	EnrollmentTokenFile string
	EsploraURL          string
}

// Runtime owns the Service and its SQLite connection for one process lifetime.
type Runtime struct {
	handler http.Handler
	service *provider.Service
	ledger  *policy.Ledger
}

// Handler returns the constrained HTTP API. The underlying Service and its
// policy-agnostic final signer stay private to this package.
func (r *Runtime) Handler() http.Handler {
	if r == nil {
		return http.NotFoundHandler()
	}
	return r.handler
}

// Close releases the authoritative ledger.
func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	if r.service != nil {
		zero(r.service.CredentialIntegrityKey)
		r.service.CredentialIntegrityKey = nil
		zero(r.service.EnrollmentTokenHash)
		r.service.EnrollmentTokenHash = nil
	}
	if r.ledger == nil {
		return nil
	}
	return r.ledger.Close()
}

type publisherDialer func(context.Context, string, string) (provider.Broadcaster, error)
type arkadeSignerDialer func(context.Context, string, *btcec.PublicKey, []string, bool) (provider.Signer, provider.PublicEmulatorIdentity, error)

// Open constructs the Mutinynet authorizer and checkpoint-pins its publisher.
func Open(ctx context.Context, cfg Config) (*Runtime, error) {
	return openWithDialers(ctx, cfg, func(ctx context.Context, baseURL, network string) (provider.Broadcaster, error) {
		return provider.DialEsplora(ctx, baseURL, network)
	}, provider.DialPublicEmulator)
}

func openWithDialers(ctx context.Context, cfg Config, dial publisherDialer, dialArkade arkadeSignerDialer) (*Runtime, error) {
	if err := cfg.Deployment.Validate(); err != nil {
		return nil, fmt.Errorf("deployment: %w", err)
	}
	if cfg.Deployment.Network != deployment.NetworkMutinynet {
		return nil, fmt.Errorf("protected authorizer is mutinynet-only")
	}
	if !filepath.IsAbs(cfg.DatabasePath) || cfg.DatabasePath == "/" || strings.Contains(strings.ToLower(cfg.DatabasePath), "mode=memory") {
		return nil, fmt.Errorf("authoritative database must be an absolute on-disk file path")
	}
	if cfg.EsploraURL == "" {
		return nil, fmt.Errorf("mutinynet esplora url required")
	}
	if dial == nil {
		return nil, fmt.Errorf("publisher dialer required")
	}
	if dialArkade == nil {
		return nil, fmt.Errorf("public arkade emulator dialer required")
	}

	providerKey, err := LoadProviderKey(cfg.ProviderKeyFile)
	if err != nil {
		return nil, err
	}
	offline, err := parseOfflinePub(cfg.OfflinePubHex)
	if err != nil {
		return nil, err
	}
	if sameXOnly(providerKey.PubKey(), offline) {
		return nil, fmt.Errorf("provider and offline keys must be independent")
	}
	arkadeBase, err := parsePinnedArkadePub(deployment.MutinynetArkadeEmulatorPubHex)
	if err != nil {
		return nil, err
	}
	if sameXOnly(providerKey.PubKey(), arkadeBase) || sameXOnly(offline, arkadeBase) {
		return nil, fmt.Errorf("public arkade emulator key must be independent from provider and offline keys")
	}
	ledger, err := policy.OpenLedger(cfg.DatabasePath, nil)
	if err != nil {
		return nil, fmt.Errorf("authoritative ledger: %w", err)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = ledger.Close()
		}
	}()
	credentialIntegrityKey, err := deriveCredentialIntegrityKey(providerKey)
	if err != nil {
		return nil, err
	}

	persisted, err := ledger.GetCredential()
	if err != nil {
		zero(credentialIntegrityKey)
		return nil, err
	}
	allowActiveDeprecated := false
	if persisted != nil {
		if err := policy.VerifyCredentialIntegrity(persisted, credentialIntegrityKey); err != nil {
			zero(credentialIntegrityKey)
			return nil, fmt.Errorf("stored credential integrity: %w; restore a trusted backup or perform an explicit migration; do not delete the authoritative database", err)
		}
		arkadeBase, err = btcec.ParsePubKey(persisted.ArkadeBase)
		if err != nil || !bytes.Equal(arkadeBase.SerializeCompressed(), persisted.ArkadeBase) {
			zero(credentialIntegrityKey)
			return nil, fmt.Errorf("stored public arkade emulator base key is invalid")
		}
		allowActiveDeprecated = true
	}

	var enrollmentTokenHash []byte
	if persisted == nil {
		if cfg.EnrollmentTokenFile == "" {
			zero(credentialIntegrityKey)
			return nil, fmt.Errorf("unenrolled authorizer requires an enrollment token file")
		}
		token, err := readBoundedSecret(cfg.EnrollmentTokenFile, "enrollment token", 32, 256)
		if err != nil {
			zero(credentialIntegrityKey)
			return nil, err
		}
		digest := sha256.Sum256(token)
		enrollmentTokenHash = append([]byte(nil), digest[:]...)
		zero(token)
	}

	arkadeSigner, arkadeIdentity, err := dialArkade(
		ctx,
		deployment.MutinynetArkadeEmulatorOrigin,
		arkadeBase,
		[]string{deployment.MutinynetArkadeEmulatorVersion},
		allowActiveDeprecated,
	)
	if err != nil {
		zero(enrollmentTokenHash)
		zero(credentialIntegrityKey)
		return nil, err
	}
	svc := &provider.Service{
		Ledger:                 ledger,
		Deployment:             cfg.Deployment,
		CredentialIntegrityKey: credentialIntegrityKey,
		Offline:                offline,
		ProviderPub:            providerKey.PubKey(),
		ArkadePub:              arkadeIdentity.BasePub,
		ArkadeEmulatorOrigin:   arkadeIdentity.Origin,
		ArkadeEmulatorVersion:  arkadeIdentity.Version,
		Signer:                 provider.LocalSigner{Priv: providerKey},
		ArkadeSigner:           arkadeSigner,
		EnrollmentTokenHash:    enrollmentTokenHash,
	}
	defer func() {
		if closeOnError {
			zero(svc.EnrollmentTokenHash)
			zero(svc.CredentialIntegrityKey)
		}
	}()
	// Authenticate and rebuild persisted state before contacting the external
	// publisher. The public cosigner was contacted only after the bootstrap
	// secret or persisted credential MAC was validated above.
	if err := svc.LoadVaults(); err != nil {
		return nil, err
	}

	publisher, err := dial(ctx, cfg.EsploraURL, cfg.Deployment.Network)
	if err != nil {
		return nil, fmt.Errorf("publisher: %w", err)
	}
	if publisher == nil {
		return nil, fmt.Errorf("publisher not configured")
	}
	svc.Broadcaster = publisher

	closeOnError = false
	return &Runtime{handler: provider.AuthorizerHandler(svc), service: svc, ledger: ledger}, nil
}

func parsePinnedArkadePub(encoded string) (*btcec.PublicKey, error) {
	if len(encoded) != 66 || encoded != strings.ToLower(encoded) {
		return nil, fmt.Errorf("public arkade emulator pubkey must be canonical 33-byte compressed lowercase hex")
	}
	raw, err := hex.DecodeString(encoded)
	if err != nil || len(raw) != 33 || (raw[0] != 0x02 && raw[0] != 0x03) {
		return nil, fmt.Errorf("public arkade emulator pubkey must be canonical 33-byte compressed lowercase hex")
	}
	pub, err := btcec.ParsePubKey(raw)
	if err != nil || !bytes.Equal(pub.SerializeCompressed(), raw) {
		return nil, fmt.Errorf("public arkade emulator pubkey is invalid")
	}
	return pub, nil
}

const (
	credentialIntegrityHKDFSalt = "arkade-2fa-vault/provider-scalar-hkdf-salt/v1"
	credentialIntegrityHKDFInfo = "arkade-2fa-vault/credential-integrity-key/v1"
)

// deriveCredentialIntegrityKey implements the one-block RFC 5869
// HKDF-SHA256 extract+expand needed for the 32-byte record MAC key. The
// provider scalar is input keying material, never the HMAC key directly.
func deriveCredentialIntegrityKey(providerKey *btcec.PrivateKey) ([]byte, error) {
	if providerKey == nil {
		return nil, fmt.Errorf("provider key required for credential integrity")
	}
	ikm := providerKey.Serialize()
	defer zero(ikm)
	extract := hmac.New(sha256.New, []byte(credentialIntegrityHKDFSalt))
	_, _ = extract.Write(ikm)
	prk := extract.Sum(nil)
	defer zero(prk)
	expand := hmac.New(sha256.New, prk)
	_, _ = expand.Write([]byte(credentialIntegrityHKDFInfo))
	_, _ = expand.Write([]byte{1})
	return expand.Sum(nil), nil
}

// LoadProviderKey reads exactly one strict secp256k1 scalar from a bounded
// hex file. btcec.PrivKeyFromBytes is called only after rejecting zero and
// every value greater than or equal to the curve order.
func LoadProviderKey(path string) (*btcec.PrivateKey, error) {
	encoded, err := readBoundedSecret(path, "provider key", 64, 64)
	if err != nil {
		return nil, err
	}
	defer zero(encoded)
	raw := make([]byte, 32)
	if _, err := hex.Decode(raw, encoded); err != nil {
		zero(raw)
		return nil, fmt.Errorf("provider key must be exactly 32-byte hex")
	}
	defer zero(raw)
	scalar := new(big.Int).SetBytes(raw)
	if scalar.Sign() <= 0 || scalar.Cmp(btcec.S256().N) >= 0 {
		return nil, fmt.Errorf("provider key scalar must be in [1, secp256k1.N-1]")
	}
	priv, _ := btcec.PrivKeyFromBytes(raw)
	fixturePub, err := fixtureOfflinePub()
	if err != nil {
		return nil, err
	}
	if sameXOnly(priv.PubKey(), fixturePub) {
		return nil, fmt.Errorf("public generator-G fixture provider key is forbidden")
	}
	return priv, nil
}

func parseOfflinePub(encoded string) (*btcec.PublicKey, error) {
	raw, err := hex.DecodeString(encoded)
	if err != nil || len(raw) != 33 || (raw[0] != 0x02 && raw[0] != 0x03) {
		return nil, fmt.Errorf("offline pubkey must be 33-byte compressed hex")
	}
	pub, err := btcec.ParsePubKey(raw)
	if err != nil {
		return nil, fmt.Errorf("offline pubkey: %w", err)
	}
	fixturePub, err := fixtureOfflinePub()
	if err != nil {
		return nil, err
	}
	if sameXOnly(pub, fixturePub) {
		return nil, fmt.Errorf("public generator-G offline fixture is forbidden")
	}
	return pub, nil
}

func fixtureOfflinePub() (*btcec.PublicKey, error) {
	raw, err := hex.DecodeString(fixture.OfflinePubHex)
	if err != nil {
		return nil, fmt.Errorf("invalid compiled fixture")
	}
	return btcec.ParsePubKey(raw)
}

func sameXOnly(a, b *btcec.PublicKey) bool {
	return a != nil && b != nil && bytes.Equal(schnorr.SerializePubKey(a), schnorr.SerializePubKey(b))
}

func readBoundedSecret(path, name string, min, max int64) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("%s file required", name)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s file: %w", name, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%s file: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file", name)
	}
	raw, err := io.ReadAll(io.LimitReader(f, max+2))
	if err != nil {
		return nil, fmt.Errorf("%s file: %w", name, err)
	}
	if int64(len(raw)) > max+1 {
		zero(raw)
		return nil, fmt.Errorf("%s file is too large", name)
	}
	secret := raw
	if len(secret) > 0 && secret[len(secret)-1] == '\n' {
		secret = secret[:len(secret)-1]
	}
	if int64(len(secret)) < min || int64(len(secret)) > max {
		zero(raw)
		return nil, fmt.Errorf("%s must contain %d..%d bytes", name, min, max)
	}
	out := append([]byte(nil), secret...)
	zero(raw)
	return out, nil
}

func zero(raw []byte) {
	for i := range raw {
		raw[i] = 0
	}
}
