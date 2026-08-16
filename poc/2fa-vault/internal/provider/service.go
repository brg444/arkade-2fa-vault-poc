package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/emulator/poc/2fa-vault/fixture"
	"github.com/arkade-os/emulator/poc/2fa-vault/internal/deployment"
	"github.com/arkade-os/emulator/poc/2fa-vault/internal/policy"
	"github.com/arkade-os/emulator/poc/2fa-vault/internal/vault"
	"github.com/arkade-os/emulator/poc/2fa-vault/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

// Service is the trusted provider authorization boundary.
type Service struct {
	Ledger     *policy.Ledger
	Deployment deployment.Config
	// CredentialIntegrityKey authenticates the immutable descriptor stored in
	// the authoritative ledger. Production obtains this key from the provider
	// scalar through a domain-separated KDF; regtest uses a public deterministic
	// test key so existing demo deployments retain corruption detection.
	CredentialIntegrityKey []byte
	// EnrollmentTokenHash gates the first and only enrollment. Once a
	// credential exists, the token is never consulted again; only the exact
	// persisted tuple remains idempotent.
	EnrollmentTokenHash   []byte
	Hot                   *btcec.PublicKey
	Offline               *btcec.PublicKey
	ProviderPub           *btcec.PublicKey
	DeprecatedProvider    []*btcec.PublicKey
	ArkadePub             *btcec.PublicKey
	DeprecatedArkade      []*btcec.PublicKey
	ArkadeEmulatorOrigin  string
	ArkadeEmulatorVersion string
	Operational           *vault.Built
	Savings               *vault.Built
	// Signer is the private Provider-key stage. ArkadeSigner is the independent
	// public Emulator stage and must never hold the private Provider key.
	Signer       Signer
	ArkadeSigner Signer
	SignTimeout  time.Duration
	// MaxConcurrentVerifications bounds the CPU-heavy WebAuthn, P-256 and
	// Schnorr verification stage. Zero uses the conservative default.
	MaxConcurrentVerifications int
	Broadcaster                Broadcaster
	mu                         sync.Mutex
	published                  atomic.Pointer[enrolledSnapshot]
	verificationOnce           sync.Once
	verificationSlots          chan struct{}
}

const defaultConcurrentVerifications = 4

const regtestCredentialIntegrityDomain = "arkade-2fa-vault/regtest-public-credential-integrity-key/v1"

var ErrVerificationBusy = errors.New("crypto verification capacity exhausted")

// enrolledSnapshot is one immutable published enrollment. Register and
// LoadVaults store a single pointer; readers load that pointer only.
type enrolledSnapshot struct {
	Hot          *btcec.PublicKey
	Offline      *btcec.PublicKey
	ProviderBase *btcec.PublicKey
	ArkadeBase   *btcec.PublicKey
	Operational  *vault.Built
	Savings      *vault.Built
}

// RegisterRequest is the enrollment payload. All byte fields are hex.
// A second call is accepted only when it matches the already-enrolled
// credential ID, WebAuthn P-256, DirectP256, and hot pub, and this
// process's offline/provider/policy still rebuild the stored descriptor.
type RegisterRequest struct {
	CredentialID string `json:"credentialId"`
	WebAuthnP256 string `json:"webauthnP256"`
	DirectP256   string `json:"directP256"`
	HotPub       string `json:"hotPub"`
}

func (s *Service) Register(req RegisterRequest) error {
	return s.RegisterWithBootstrap(req, "")
}

// RegisterWithBootstrap requires the deployment bootstrap token only while
// the ledger is unenrolled. Errors never include token material.
func (s *Service) RegisterWithBootstrap(req RegisterRequest, bootstrap string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.runtimeConfig().Validate(); err != nil {
		return fmt.Errorf("deployment: %w", err)
	}

	id, webauthnP256, directP256, hot, err := parseRegisterRequest(req, s.Hot)
	if err != nil {
		return err
	}

	existing, err := s.loadVerifiedCredential()
	if err != nil {
		return err
	}
	if existing != nil {
		if err := s.acceptPersistedEnrollment(existing, id, webauthnP256, directP256, hot); err != nil {
			return err
		}
		s.clearEnrollmentTokenHash()
		return nil
	}
	if s.runtimeConfig().Network != deployment.NetworkRegtest && len(s.EnrollmentTokenHash) != sha256.Size {
		return fmt.Errorf("enrollment bootstrap authorization is not configured")
	}
	if len(s.EnrollmentTokenHash) > 0 {
		got := sha256.Sum256([]byte(bootstrap))
		if len(s.EnrollmentTokenHash) != sha256.Size || subtle.ConstantTimeCompare(got[:], s.EnrollmentTokenHash) != 1 {
			return fmt.Errorf("enrollment bootstrap authorization failed")
		}
	}

	op, sv, err := s.makeTrees(hot, directP256)
	if err != nil {
		return err
	}
	descriptor := descriptorFromTrees(
		s.runtimeConfig(), id, webauthnP256, directP256,
		hot, s.Offline, s.ProviderPub, s.ArkadePub,
		s.ArkadeEmulatorOrigin, s.ArkadeEmulatorVersion, op, sv,
	)
	if err := s.sealCredential(&descriptor); err != nil {
		return err
	}
	if err := s.Ledger.Enroll(descriptor); err != nil {
		existing, getErr := s.loadVerifiedCredential()
		if getErr != nil {
			return err
		}
		if existing == nil {
			return err
		}
		if err := s.acceptPersistedEnrollment(existing, id, webauthnP256, directP256, hot); err != nil {
			return err
		}
		s.clearEnrollmentTokenHash()
		return nil
	}
	s.bindRemoteExpected(op)
	s.publishEnrollment(hot, op, sv)
	s.clearEnrollmentTokenHash()
	return nil
}

func (s *Service) clearEnrollmentTokenHash() {
	for i := range s.EnrollmentTokenHash {
		s.EnrollmentTokenHash[i] = 0
	}
	s.EnrollmentTokenHash = nil
}

// acceptPersistedEnrollment succeeds only for the exact user tuple when
// runtime config matches the stored descriptor and trees rebuilt from that
// record equal the persisted addresses/scripts/tweaked provider. It never
// publishes trees derived from this process's speculative Offline/Provider.
func (s *Service) acceptPersistedEnrollment(existing *policy.Credential, id, webauthnP256, directP256 []byte, hot *btcec.PublicKey) error {
	if !sameEnrollmentTuple(existing, id, webauthnP256, directP256, hot) {
		return fmt.Errorf("enrollment locked")
	}
	return s.publishStoredEnrollment(existing, false)
}

func parseRegisterRequest(req RegisterRequest, fallbackHot *btcec.PublicKey) (id, webauthnP256, directP256 []byte, hot *btcec.PublicKey, err error) {
	id, err = decodeHex(req.CredentialID)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("credentialId: %w", err)
	}
	webauthnP256, err = decodeHex(req.WebAuthnP256)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("webauthnP256: %w", err)
	}
	if _, err = webauthn.ParseCompressedP256(webauthnP256); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("webauthnP256: %w", err)
	}
	directP256, err = decodeHex(req.DirectP256)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("directP256: %w", err)
	}
	if _, err = webauthn.ParseCompressedP256(directP256); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("directP256: %w", err)
	}
	if bytes.Equal(webauthnP256, directP256) {
		return nil, nil, nil, nil, fmt.Errorf("direct-auth p256 must be distinct from the webauthn credential p256")
	}
	hot, err = parseHotPub(req.HotPub, fallbackHot)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return id, webauthnP256, directP256, hot, nil
}

func sameEnrollmentTuple(c *policy.Credential, id, webauthnP256, directP256 []byte, hot *btcec.PublicKey) bool {
	return c != nil && hot != nil &&
		bytes.Equal(c.ID, id) &&
		bytes.Equal(c.WebAuthnP256, webauthnP256) &&
		bytes.Equal(c.DirectP256, directP256) &&
		bytes.Equal(c.Hot, hot.SerializeCompressed())
}

// LoadVaults rebuilds trees from the persisted enrollment descriptor.
// Runtime config must be compatible; trees are never derived from a
// rotated GetInfo key or a changed CSV/network/template.
func (s *Service) LoadVaults() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.runtimeConfig().Validate(); err != nil {
		return fmt.Errorf("deployment: %w", err)
	}
	cred, err := s.loadVerifiedCredential()
	if err != nil {
		return err
	}
	if cred == nil {
		return nil
	}
	return s.publishStoredEnrollment(cred, true)
}

func (s *Service) publishStoredEnrollment(cred *policy.Credential, startup bool) error {
	hot, offline, providerBase, arkadeBase, op, sv, err := s.rebuildFromCredential(cred)
	if err != nil {
		return err
	}
	runtimeProvider := s.ProviderPub
	// Startup may replace a deprecated/current RemoteSigner identity with the
	// persisted vault identity after compatibility is checked. An idempotent
	// /register never rewrites fields read by concurrent requests.
	if startup {
		s.Offline = offline
		s.ProviderPub = providerBase
		s.ArkadePub = arkadeBase
	}
	s.bindRemoteExpected(op)
	s.publishEnrollment(hot, op, sv)
	if runtimeProvider != nil && !sameCompressed(runtimeProvider, cred.ProviderBase) {
		log.Printf("rebuilt vault from enrolled provider base %x; current runtime signer %x must remain deprecated",
			cred.ProviderBase, runtimeProvider.SerializeCompressed())
	}
	return nil
}

func (s *Service) rebuildFromCredential(cred *policy.Credential) (hot, offline, providerBase, arkadeBase *btcec.PublicKey, op, sv *vault.Built, err error) {
	if err = s.requireCompatible(cred); err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	hot, err = btcec.ParsePubKey(cred.Hot)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("stored hot: %w", err)
	}
	offline, err = btcec.ParsePubKey(cred.Offline)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("stored offline: %w", err)
	}
	providerBase, err = btcec.ParsePubKey(cred.ProviderBase)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("stored provider: %w", err)
	}
	arkadeBase, err = btcec.ParsePubKey(cred.ArkadeBase)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("stored arkade emulator: %w", err)
	}
	opCSV := arklib.RelativeLocktime{Type: arklib.RelativeLocktimeType(cred.OperationalCSVType), Value: cred.OperationalCSVValue}
	svCSV := arklib.RelativeLocktime{Type: arklib.RelativeLocktimeType(cred.SavingsCSVType), Value: cred.SavingsCSVValue}
	op, err = vault.NewFromRecord(vault.Record{
		Kind:                vault.Operational,
		Hot:                 hot,
		Offline:             offline,
		ProviderBase:        providerBase,
		ArkadeBase:          arkadeBase,
		DirectP256:          cred.DirectP256,
		CSV:                 opCSV,
		AuthorizationPolicy: authorizationPolicyFromCredential(cred),
		Network:             cred.Network,
	})
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	sv, err = vault.NewFromRecord(vault.Record{
		Kind:    vault.Savings,
		Hot:     hot,
		Offline: offline,
		CSV:     svCSV,
		Network: cred.Network,
	})
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	if err = sv.AssertNoProvider(providerBase, op.TweakedProvider, arkadeBase, op.TweakedArkade); err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	if op.Address != cred.OperationalAddress || !bytes.Equal(op.PkScript, cred.OperationalScript) {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("rebuilt operational vault does not match stored descriptor")
	}
	if sv.Address != cred.SavingsAddress || !bytes.Equal(sv.PkScript, cred.SavingsScript) {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("rebuilt savings vault does not match stored descriptor")
	}
	if op.TweakedProvider == nil || !bytes.Equal(op.TweakedProvider.SerializeCompressed(), cred.TweakedProvider) {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("rebuilt tweaked provider does not match stored descriptor")
	}
	if op.TweakedArkade == nil || !bytes.Equal(op.TweakedArkade.SerializeCompressed(), cred.TweakedArkade) {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("rebuilt tweaked arkade emulator does not match stored descriptor")
	}
	return hot, offline, providerBase, arkadeBase, op, sv, nil
}

func (s *Service) makeTrees(hot *btcec.PublicKey, directP256 []byte) (*vault.Built, *vault.Built, error) {
	if hot == nil || s.Offline == nil || s.ProviderPub == nil || s.ArkadePub == nil {
		return nil, nil, fmt.Errorf("vault keys not configured")
	}
	cfg := s.runtimeConfig()
	opCSV := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: cfg.OperationalCSVBlocks}
	svCSV := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: cfg.SavingsCSVBlocks}
	op, err := vault.NewOperationalWithPolicy(vault.OperationalKeys{
		Hot: hot, Offline: s.Offline, ProviderBase: s.ProviderPub,
		ArkadeBase: s.ArkadePub, DirectP256: directP256,
	}, cfg.Network, opCSV, configuredAuthorizationPolicy())
	if err != nil {
		return nil, nil, err
	}
	sv, err := vault.NewSavingsWithPolicy(
		hot, s.Offline, cfg.Network, svCSV,
		s.ProviderPub, op.TweakedProvider, s.ArkadePub, op.TweakedArkade,
	)
	if err != nil {
		return nil, nil, err
	}
	return op, sv, nil
}

func descriptorFromTrees(
	cfg deployment.Config, id, webauthnP256, directP256 []byte,
	hot, offline, providerBase, arkadeBase *btcec.PublicKey,
	arkadeOrigin, arkadeVersion string, op, sv *vault.Built,
) policy.Credential {
	opCSV := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: cfg.OperationalCSVBlocks}
	svCSV := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: cfg.SavingsCSVBlocks}
	return policy.Credential{
		ID:                    id,
		WebAuthnP256:          append([]byte(nil), webauthnP256...),
		DirectP256:            append([]byte(nil), directP256...),
		Hot:                   hot.SerializeCompressed(),
		RPID:                  cfg.RPID,
		Origin:                cfg.ClientOrigin,
		Offline:               offline.SerializeCompressed(),
		ProviderBase:          providerBase.SerializeCompressed(),
		TweakedProvider:       op.TweakedProvider.SerializeCompressed(),
		ArkadeBase:            arkadeBase.SerializeCompressed(),
		TweakedArkade:         op.TweakedArkade.SerializeCompressed(),
		ArkadeEmulatorOrigin:  arkadeOrigin,
		ArkadeEmulatorVersion: arkadeVersion,
		TemplateVersion:       fixture.TemplateVersion,
		PolicyVersion:         fixture.PolicyVersion,
		Network:               cfg.Network,
		VaultID:               fixture.VaultID,
		OperationalCSVType:    int64(opCSV.Type),
		OperationalCSVValue:   opCSV.Value,
		SavingsCSVType:        int64(svCSV.Type),
		SavingsCSVValue:       svCSV.Value,
		OperationalAddress:    op.Address,
		OperationalScript:     append([]byte(nil), op.PkScript...),
		SavingsAddress:        sv.Address,
		SavingsScript:         append([]byte(nil), sv.PkScript...),
		RecipientDustSats:     fixture.DustSats,
		TxRecipientCapSats:    fixture.TxRecipientCapSats,
		PeriodAllowanceSats:   fixture.PeriodAllowanceSats,
		AbsoluteFeeCapSats:    fixture.AbsoluteFeeCeiling,
		FeerateCapSatPerV:     fixture.FeerateCeilingSatPerV,
	}
}

func configuredAuthorizationPolicy() vault.AuthorizationPolicy {
	return vault.AuthorizationPolicy{
		RecipientDustSats:      fixture.DustSats,
		RecipientCapSats:       fixture.TxRecipientCapSats,
		AbsoluteFeeCeilingSats: fixture.AbsoluteFeeCeiling,
		FeerateCeilingSatPerV:  fixture.FeerateCeilingSatPerV,
	}
}

func authorizationPolicyFromCredential(cred *policy.Credential) vault.AuthorizationPolicy {
	return vault.AuthorizationPolicy{
		RecipientDustSats:      cred.RecipientDustSats,
		RecipientCapSats:       cred.TxRecipientCapSats,
		AbsoluteFeeCeilingSats: cred.AbsoluteFeeCapSats,
		FeerateCeilingSatPerV:  cred.FeerateCapSatPerV,
	}
}

func (s *Service) requireCompatible(cred *policy.Credential) error {
	cfg := s.runtimeConfig()
	if cred.TemplateVersion != fixture.TemplateVersion {
		return fmt.Errorf("stored template %q incompatible with runtime %q", cred.TemplateVersion, fixture.TemplateVersion)
	}
	if cred.PolicyVersion != fixture.PolicyVersion {
		return fmt.Errorf("stored policy %q incompatible with runtime %q", cred.PolicyVersion, fixture.PolicyVersion)
	}
	if cred.Network != cfg.Network {
		return fmt.Errorf("stored network %q incompatible with runtime %q", cred.Network, cfg.Network)
	}
	if cred.VaultID != fixture.VaultID {
		return fmt.Errorf("stored vault id %q incompatible with runtime %q", cred.VaultID, fixture.VaultID)
	}
	opCSV := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: cfg.OperationalCSVBlocks}
	svCSV := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: cfg.SavingsCSVBlocks}
	if cred.OperationalCSVType != int64(opCSV.Type) || cred.OperationalCSVValue != opCSV.Value {
		return fmt.Errorf("stored operational CSV incompatible with runtime")
	}
	if cred.SavingsCSVType != int64(svCSV.Type) || cred.SavingsCSVValue != svCSV.Value {
		return fmt.Errorf("stored savings CSV incompatible with runtime")
	}
	if cred.Origin != cfg.ClientOrigin {
		return fmt.Errorf("stored origin %q incompatible with runtime %q", cred.Origin, cfg.ClientOrigin)
	}
	if cred.RPID != cfg.RPID {
		return fmt.Errorf("stored rp id %q incompatible with runtime %q", cred.RPID, cfg.RPID)
	}
	if cred.RecipientDustSats != fixture.DustSats ||
		cred.TxRecipientCapSats != fixture.TxRecipientCapSats ||
		cred.PeriodAllowanceSats != fixture.PeriodAllowanceSats ||
		cred.AbsoluteFeeCapSats != fixture.AbsoluteFeeCeiling ||
		cred.FeerateCapSatPerV != fixture.FeerateCeilingSatPerV {
		return fmt.Errorf("stored economic policy incompatible with runtime")
	}
	if cred.ArkadeEmulatorOrigin != s.ArkadeEmulatorOrigin {
		return fmt.Errorf("stored arkade emulator origin %q incompatible with runtime %q", cred.ArkadeEmulatorOrigin, s.ArkadeEmulatorOrigin)
	}
	if cfg.Network != deployment.NetworkRegtest && (cred.ArkadeEmulatorVersion == "" || s.ArkadeEmulatorVersion == "") {
		return fmt.Errorf("stored and runtime arkade emulator versions are required")
	}
	// The persisted value records the exact reviewed version at enrollment.
	// Runtime separately accepts only its release allowlist. They need not be
	// equal after a reviewed key/version rotation: an existing descriptor stays
	// live only when its exact MAC-authenticated key is still advertised as an
	// active deprecated signer.
	if s.Offline != nil && !sameCompressed(s.Offline, cred.Offline) {
		return fmt.Errorf("runtime offline pubkey does not match enrolled vault")
	}
	if err := requireSignerCompatible("provider", s.ProviderPub, s.DeprecatedProvider, cred.ProviderBase); err != nil {
		return err
	}
	if err := requireSignerCompatible("arkade emulator", s.ArkadePub, s.DeprecatedArkade, cred.ArkadeBase); err != nil {
		return err
	}
	return nil
}

func requireSignerCompatible(name string, current *btcec.PublicKey, deprecated []*btcec.PublicKey, stored []byte) error {
	if current == nil && len(deprecated) == 0 {
		return nil
	}
	if current != nil && sameCompressed(current, stored) {
		return nil
	}
	for _, pub := range deprecated {
		if sameCompressed(pub, stored) {
			return nil
		}
	}
	return fmt.Errorf("enrolled %s key does not match the configured runtime signer or an allowed deprecated key", name)
}

func sameCompressed(pub *btcec.PublicKey, raw []byte) bool {
	return pub != nil && bytes.Equal(pub.SerializeCompressed(), raw)
}

func (s *Service) bindRemoteExpected(op *vault.Built) {
	if op == nil {
		return
	}
	if binder, ok := s.Signer.(interface{ BindExpectedSigner([]byte) }); ok && op.TweakedProvider != nil {
		binder.BindExpectedSigner(schnorr.SerializePubKey(op.TweakedProvider))
	}
	if binder, ok := s.ArkadeSigner.(interface{ BindExpectedSigner([]byte) }); ok && op.TweakedArkade != nil {
		binder.BindExpectedSigner(schnorr.SerializePubKey(op.TweakedArkade))
	}
}

func parseHotPub(hexPub string, fallback *btcec.PublicKey) (*btcec.PublicKey, error) {
	if hexPub == "" {
		if fallback == nil {
			return nil, fmt.Errorf("hotPub required")
		}
		return fallback, nil
	}
	raw, err := decodeHex(hexPub)
	if err != nil {
		return nil, fmt.Errorf("hotPub: %w", err)
	}
	pub, err := btcec.ParsePubKey(raw)
	if err != nil {
		return nil, fmt.Errorf("hotPub: %w", err)
	}
	return pub, nil
}

// Status is the UI snapshot.
type Status struct {
	Enrolled                     bool   `json:"enrolled"`
	Network                      string `json:"network"`
	ClientOrigin                 string `json:"clientOrigin"`
	RPID                         string `json:"rpId"`
	VaultID                      string `json:"vaultId"`
	TemplateVersion              string `json:"templateVersion"`
	PolicyVersion                string `json:"policyVersion"`
	OperationalCSVBlocks         uint32 `json:"operationalCsvBlocks"`
	SavingsCSVBlocks             uint32 `json:"savingsCsvBlocks"`
	BackupPub                    string `json:"backupPub,omitempty"`
	ProviderBasePub              string `json:"providerBasePub,omitempty"`
	ArkadeEmulatorBasePub        string `json:"arkadeEmulatorBasePub,omitempty"`
	ArkadeEmulatorOrigin         string `json:"arkadeEmulatorOrigin,omitempty"`
	ArkadeEmulatorVersion        string `json:"arkadeEmulatorVersion,omitempty"`
	OperationalAddr              string `json:"operationalAddress"`
	OperationalScript            string `json:"operationalScript,omitempty"`
	SavingsAddr                  string `json:"savingsAddress"`
	SavingsExcludesProvider      bool   `json:"savingsExcludesProvider"`
	SavingsExcludesCollaborators bool   `json:"savingsExcludesCollaborators"`
	PeriodAllowance              int64  `json:"periodAllowance"`
	PeriodSpent                  int64  `json:"periodSpent"`
	PeriodRemaining              int64  `json:"periodRemaining"`
	TxCap                        int64  `json:"txCap"`
	AbsoluteFeeCap               int64  `json:"absoluteFeeCap"`
	FeerateCapSatPerV            int64  `json:"feerateCapSatVb"`
	HotPub                       string `json:"hotPub,omitempty"`
	DirectP256                   string `json:"directP256,omitempty"`
	TweakedProviderXOnly         string `json:"tweakedProviderXOnly,omitempty"`
	TweakedArkadeXOnly           string `json:"tweakedArkadeXOnly,omitempty"`
}

func (s *Service) publishEnrollment(hot *btcec.PublicKey, op, sv *vault.Built) {
	snap := &enrolledSnapshot{Hot: hot, Operational: op, Savings: sv}
	if op != nil {
		snap.Offline = op.Record.Offline
		snap.ProviderBase = op.Record.ProviderBase
		snap.ArkadeBase = op.Record.ArkadeBase
	}
	s.published.Store(snap)
	// Keep exported legacy/test fields stable after their first publication.
	if s.Hot == nil {
		s.Hot = hot
	}
	if s.Operational == nil {
		s.Operational = op
	}
	if s.Savings == nil {
		s.Savings = sv
	}
}

func (s *Service) enrolled() enrolledSnapshot {
	if snap := s.published.Load(); snap != nil {
		return *snap
	}
	return enrolledSnapshot{}
}

func (s *Service) Status(ctx context.Context) (Status, error) {
	cfg := s.runtimeConfig()
	if err := cfg.Validate(); err != nil {
		return Status{}, fmt.Errorf("deployment: %w", err)
	}
	cred, err := s.loadVerifiedCredential()
	if err != nil {
		return Status{}, err
	}
	spent, err := s.Ledger.SpentInPeriod(ctx, fixture.VaultID, s.Ledger.PeriodStart())
	if err != nil {
		return Status{}, err
	}
	rem := fixture.PeriodAllowanceSats - spent
	if rem < 0 {
		rem = 0
	}
	st := Status{
		Enrolled:             cred != nil,
		Network:              cfg.Network,
		ClientOrigin:         cfg.ClientOrigin,
		RPID:                 cfg.RPID,
		VaultID:              fixture.VaultID,
		TemplateVersion:      fixture.TemplateVersion,
		PolicyVersion:        fixture.PolicyVersion,
		OperationalCSVBlocks: cfg.OperationalCSVBlocks,
		SavingsCSVBlocks:     cfg.SavingsCSVBlocks,
		PeriodAllowance:      fixture.PeriodAllowanceSats,
		PeriodSpent:          spent,
		PeriodRemaining:      rem,
		TxCap:                fixture.TxRecipientCapSats,
		AbsoluteFeeCap:       fixture.AbsoluteFeeCeiling,
		FeerateCapSatPerV:    fixture.FeerateCeilingSatPerV,
	}
	snap := s.enrolled()
	if cred == nil {
		if s.Offline != nil {
			st.BackupPub = hex.EncodeToString(s.Offline.SerializeCompressed())
		}
		if s.ProviderPub != nil {
			st.ProviderBasePub = hex.EncodeToString(s.ProviderPub.SerializeCompressed())
		}
		if s.ArkadePub != nil {
			st.ArkadeEmulatorBasePub = hex.EncodeToString(s.ArkadePub.SerializeCompressed())
		}
	}
	if cred != nil {
		// Report the persisted descriptor inputs, not merely mutable runtime
		// fields. LoadVaults/Register already require these to match runtime.
		st.BackupPub = hex.EncodeToString(cred.Offline)
		st.ProviderBasePub = hex.EncodeToString(cred.ProviderBase)
		st.ArkadeEmulatorBasePub = hex.EncodeToString(cred.ArkadeBase)
		st.ArkadeEmulatorOrigin = cred.ArkadeEmulatorOrigin
		st.ArkadeEmulatorVersion = cred.ArkadeEmulatorVersion
	}
	if snap.Operational != nil {
		st.OperationalAddr = snap.Operational.Address
		st.OperationalScript = hex.EncodeToString(snap.Operational.PkScript)
		if snap.Operational.TweakedProvider != nil {
			st.TweakedProviderXOnly = hex.EncodeToString(schnorr.SerializePubKey(snap.Operational.TweakedProvider))
		}
		if snap.Operational.TweakedArkade != nil {
			st.TweakedArkadeXOnly = hex.EncodeToString(schnorr.SerializePubKey(snap.Operational.TweakedArkade))
		}
	}
	if snap.Savings != nil {
		st.SavingsAddr = snap.Savings.Address
		var forbidden []*btcec.PublicKey
		if snap.ProviderBase != nil {
			forbidden = append(forbidden, snap.ProviderBase)
		}
		if snap.Operational != nil && snap.Operational.TweakedProvider != nil {
			forbidden = append(forbidden, snap.Operational.TweakedProvider)
		}
		if snap.ArkadeBase != nil {
			forbidden = append(forbidden, snap.ArkadeBase)
		}
		if snap.Operational != nil && snap.Operational.TweakedArkade != nil {
			forbidden = append(forbidden, snap.Operational.TweakedArkade)
		}
		st.SavingsExcludesProvider = snap.Savings.AssertNoProvider(forbidden...) == nil
		st.SavingsExcludesCollaborators = st.SavingsExcludesProvider
	}
	if snap.Hot != nil {
		st.HotPub = hex.EncodeToString(snap.Hot.SerializeCompressed())
	}
	if cred != nil && len(cred.DirectP256) > 0 {
		st.DirectP256 = hex.EncodeToString(cred.DirectP256)
	}
	return st, nil
}

// DraftRequest builds an empty-witness collaborative PSBT the browser can bind.
type DraftRequest struct {
	PrevTxHex       string `json:"prevTxHex"`
	Vout            uint32 `json:"vout"`
	RecipientScript string `json:"recipientScript"`
	RecipientAmount int64  `json:"recipientAmount"`
	Fee             int64  `json:"fee"`
}

func (s *Service) Draft(req DraftRequest) (string, error) {
	return s.DraftContext(context.Background(), req)
}

// DraftContext bounds transaction parsing, hashing, classification and tree
// work under the same non-queueing verification budget as signing routes.
func (s *Service) DraftContext(ctx context.Context, req DraftRequest) (string, error) {
	op := s.enrolled().Operational
	if op == nil {
		return "", fmt.Errorf("not enrolled")
	}
	release, err := s.acquireVerification(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	raw, err := decodeHex(req.PrevTxHex)
	if err != nil {
		return "", err
	}
	prev := wire.NewMsgTx(2)
	if err := prev.Deserialize(bytes.NewReader(raw)); err != nil {
		return "", fmt.Errorf("prev tx: %w", err)
	}
	dest, err := decodeHex(req.RecipientScript)
	if err != nil {
		return "", err
	}
	built, err := vault.BuildCollaborativeSpend(vault.SpendParams{
		Vault:           op,
		PrevTx:          prev,
		PrevOutPoint:    wire.OutPoint{Hash: prev.TxHash(), Index: req.Vout},
		RecipientScript: dest,
		RecipientAmount: req.RecipientAmount,
		Fee:             req.Fee,
	})
	if err != nil {
		return "", err
	}
	if _, err := classifySpend(built.Packet, op); err != nil {
		return "", err
	}
	return built.Packet.B64Encode()
}

// BindRequest carries the off-chain WebAuthn assertion plus the compact
// direct-auth signature. Only directSig is written into the packet witness.
type BindRequest struct {
	PSBT              string `json:"psbt"`
	CredentialID      string `json:"credentialId"`
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
	DirectSig         string `json:"directSig"`
}

func (s *Service) Bind(req BindRequest) (string, error) {
	return s.BindContext(context.Background(), req)
}

// BindContext verifies and binds a direct-auth witness under the shared
// bounded crypto-verification budget.
func (s *Service) BindContext(ctx context.Context, req BindRequest) (string, error) {
	op := s.enrolled().Operational
	if op == nil {
		return "", fmt.Errorf("not enrolled")
	}
	release, err := s.acquireVerification(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	ptx, _, err := parseAndVerifyPrevout(req.PSBT)
	if err != nil {
		return "", err
	}
	if _, err := classifySpend(ptx, op); err != nil {
		return "", err
	}
	assertion, err := decodeAssertion(AuthorizeRequest{
		CredentialID: req.CredentialID, ClientDataJSON: req.ClientDataJSON,
		AuthenticatorData: req.AuthenticatorData, Signature: req.Signature,
	})
	if err != nil {
		return "", err
	}
	if err := rejectPRF(assertion.ClientDataJSON); err != nil {
		return "", err
	}
	ch, err := vault.Challenge(ptx, op)
	if err != nil {
		return "", err
	}
	cred, err := s.loadVerifiedCredential()
	if err != nil {
		return "", err
	}
	if cred == nil {
		return "", fmt.Errorf("not enrolled")
	}
	if _, err := webauthn.Validate(assertion, webauthn.Expected{
		CredentialID: cred.ID, WebAuthnP256: cred.WebAuthnP256, Challenge: ch,
		Origin: cred.Origin, RPID: cred.RPID,
	}); err != nil {
		return "", err
	}
	directSig, err := decodeHex(req.DirectSig)
	if err != nil {
		return "", fmt.Errorf("directSig: %w", err)
	}
	if err := verifyDirectAuth(cred.DirectP256, ch, directSig); err != nil {
		return "", err
	}
	if err := vault.SetPacketWitness(ptx.UnsignedTx, wire.TxWitness{directSig}); err != nil {
		return "", err
	}
	return ptx.B64Encode()
}

// PreflightRequest is a non-signing challenge request.
type PreflightRequest struct {
	PSBT string `json:"psbt"`
}

type PreflightResponse struct {
	Challenge string `json:"challenge"`
}

func (s *Service) Preflight(rawPSBT string) (*PreflightResponse, error) {
	return s.PreflightContext(context.Background(), rawPSBT)
}

// PreflightContext admits PSBT parsing and sighash computation only while a
// bounded verification slot is available.
func (s *Service) PreflightContext(ctx context.Context, rawPSBT string) (*PreflightResponse, error) {
	op := s.enrolled().Operational
	if op == nil {
		return nil, fmt.Errorf("not enrolled")
	}
	release, err := s.acquireVerification(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	ptx, _, err := parseAndVerifyPrevout(rawPSBT)
	if err != nil {
		return nil, err
	}
	if _, err := classifySpend(ptx, op); err != nil {
		return nil, err
	}
	ch, err := vault.Challenge(ptx, op)
	if err != nil {
		return nil, err
	}
	return &PreflightResponse{Challenge: hex.EncodeToString(ch)}, nil
}

// AuthorizeRequest is the field-by-field signing request. No PRF fields.
type AuthorizeRequest struct {
	PSBT              string `json:"psbt"`
	CredentialID      string `json:"credentialId"`
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
}

func (s *Service) Authorize(ctx context.Context, req AuthorizeRequest) (signedPSBT string, replay bool, err error) {
	op := s.enrolled().Operational
	if op == nil {
		return "", false, fmt.Errorf("not enrolled")
	}
	ptx, cl, challenge, err := s.verifyAuthorizeRequest(ctx, req, op)
	if err != nil {
		return "", false, err
	}

	requestPSBT, err := ptx.B64Encode()
	if err != nil {
		return "", false, err
	}
	if s.Signer == nil || s.ArkadeSigner == nil || op.TweakedProvider == nil || op.TweakedArkade == nil {
		return "", false, fmt.Errorf("both private provider and public arkade signers are required")
	}

	timeout := s.SignTimeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}

	return s.Ledger.IssueSequential(
		ctx, fixture.VaultID, challenge, requestPSBT,
		cl.Recipient.Value, cl.Fee, fixture.PeriodAllowanceSats,
		func(issueCtx context.Context, storedRequest string) (string, error) {
			if err := issueCtx.Err(); err != nil {
				return "", err
			}
			// Start the signing window only after Issue has serialized this
			// caller and committed its reservation. Creating it earlier lets a
			// queued request expire while waiting, then reserve budget and
			// call Sign with a dead context.
			signCtx, cancel := context.WithTimeout(issueCtx, timeout)
			defer cancel()
			return signExactStage(
				signCtx, storedRequest, s.Signer,
				schnorr.SerializePubKey(op.TweakedProvider), "private provider",
			)
		},
		func(issueCtx context.Context, storedProviderPSBT string) (string, error) {
			if err := issueCtx.Err(); err != nil {
				return "", err
			}
			providerStage, _, err := parseAndVerifyPrevout(storedProviderPSBT)
			if err != nil {
				return "", fmt.Errorf("stored provider stage: %w", err)
			}
			if err := verifyExactCollaborativeSignatures(
				providerStage, op, op.Record.Hot, op.TweakedProvider,
			); err != nil {
				return "", fmt.Errorf("stored provider stage: %w", err)
			}
			signCtx, cancel := context.WithTimeout(issueCtx, timeout)
			defer cancel()
			completed, err := signExactStage(
				signCtx, storedProviderPSBT, s.ArkadeSigner,
				schnorr.SerializePubKey(op.TweakedArkade), "public arkade emulator",
			)
			if err != nil {
				return "", err
			}
			completedPacket, _, err := parseAndVerifyPrevout(completed)
			if err != nil {
				return "", err
			}
			if err := verifyExactCollaborativeSignatures(
				completedPacket, op, op.Record.Hot, op.TweakedProvider, op.TweakedArkade,
			); err != nil {
				return "", err
			}
			return completed, nil
		},
	)
}

func (s *Service) verifyAuthorizeRequest(ctx context.Context, req AuthorizeRequest, op *vault.Built) (*psbt.Packet, *Classified, []byte, error) {
	release, err := s.acquireVerification(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	defer release()
	ptx, _, err := parseAndVerifyPrevout(req.PSBT)
	if err != nil {
		return nil, nil, nil, err
	}
	cl, err := classifySpend(ptx, op)
	if err != nil {
		return nil, nil, nil, err
	}
	challenge, err := s.verifyAuthorization(req, ptx, op)
	if err != nil {
		return nil, nil, nil, err
	}
	return ptx, cl, challenge, nil
}

func (s *Service) verifyAuthorization(req AuthorizeRequest, ptx *psbt.Packet, op *vault.Built) ([]byte, error) {

	assertion, err := decodeAssertion(req)
	if err != nil {
		return nil, err
	}
	if err := rejectPRF(assertion.ClientDataJSON); err != nil {
		return nil, err
	}
	cred, err := s.loadVerifiedCredential()
	if err != nil {
		return nil, err
	}
	if cred == nil {
		return nil, fmt.Errorf("not enrolled")
	}

	challenge, err := vault.Challenge(ptx, op)
	if err != nil {
		return nil, err
	}
	if _, err := webauthn.Validate(assertion, webauthn.Expected{
		CredentialID: cred.ID,
		WebAuthnP256: cred.WebAuthnP256,
		Challenge:    challenge,
		Origin:       cred.Origin,
		RPID:         cred.RPID,
	}); err != nil {
		return nil, err
	}

	packet, err := arkade.FindEmulatorPacket(ptx.UnsignedTx)
	if err != nil {
		return nil, err
	}
	if len(packet) != 1 {
		return nil, fmt.Errorf("emulator packet")
	}
	if len(packet[0].Witness) != 1 || len(packet[0].Witness[0]) != 64 {
		return nil, fmt.Errorf("packet witness must be the one-item 64-byte direct signature")
	}
	if err := verifyDirectAuth(cred.DirectP256, challenge, packet[0].Witness[0]); err != nil {
		return nil, err
	}
	if err := verifyHotSignature(ptx, op); err != nil {
		return nil, err
	}
	return challenge, nil
}

func (s *Service) acquireVerification(ctx context.Context) (func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	s.verificationOnce.Do(func() {
		limit := s.MaxConcurrentVerifications
		if limit <= 0 {
			limit = defaultConcurrentVerifications
		}
		s.verificationSlots = make(chan struct{}, limit)
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case s.verificationSlots <- struct{}{}:
		return func() { <-s.verificationSlots }, nil
	default:
		return nil, ErrVerificationBusy
	}
}

func (s *Service) runtimeConfig() deployment.Config {
	if s == nil {
		return deployment.Default()
	}
	return s.Deployment.WithDefaults()
}

func (s *Service) credentialIntegrityKey() ([]byte, error) {
	if len(s.CredentialIntegrityKey) == sha256.Size {
		return append([]byte(nil), s.CredentialIntegrityKey...), nil
	}
	if len(s.CredentialIntegrityKey) != 0 {
		return nil, fmt.Errorf("credential integrity key must be 32 bytes")
	}
	if s.runtimeConfig().Network != deployment.NetworkRegtest {
		return nil, fmt.Errorf("credential integrity key is required outside regtest")
	}
	// This is intentionally public and provides corruption detection only for
	// the disposable regtest demo. Production authorizer construction never
	// accepts this fallback.
	digest := sha256.Sum256([]byte(regtestCredentialIntegrityDomain))
	return append([]byte(nil), digest[:]...), nil
}

func (s *Service) sealCredential(cred *policy.Credential) error {
	key, err := s.credentialIntegrityKey()
	if err != nil {
		return err
	}
	defer zeroServiceBytes(key)
	if err := policy.SealCredential(cred, key); err != nil {
		return fmt.Errorf("seal credential record: %w", err)
	}
	return nil
}

func (s *Service) loadVerifiedCredential() (*policy.Credential, error) {
	key, err := s.credentialIntegrityKey()
	if err != nil {
		return nil, err
	}
	defer zeroServiceBytes(key)
	cred, err := s.Ledger.GetCredential()
	if err != nil || cred == nil {
		return cred, err
	}
	if err := policy.VerifyCredentialIntegrity(cred, key); err != nil {
		return nil, fmt.Errorf("authoritative credential integrity verification failed: %w; do not delete deployment data: stop the signer and restore a verified backup or use a reviewed migration", err)
	}
	return cred, nil
}

func zeroServiceBytes(raw []byte) {
	for i := range raw {
		raw[i] = 0
	}
}

// RuntimeConfig returns the validated public identity used by HTTP and the
// browser. Callers receive a value copy and cannot mutate Service state.
func (s *Service) RuntimeConfig() (deployment.Config, error) {
	cfg := s.runtimeConfig()
	return cfg, cfg.Validate()
}

func decodeAssertion(req AuthorizeRequest) (webauthn.Assertion, error) {
	id, err := decodeHex(req.CredentialID)
	if err != nil {
		return webauthn.Assertion{}, err
	}
	cd, err := decodeHex(req.ClientDataJSON)
	if err != nil {
		return webauthn.Assertion{}, err
	}
	ad, err := decodeHex(req.AuthenticatorData)
	if err != nil {
		return webauthn.Assertion{}, err
	}
	sig, err := decodeHex(req.Signature)
	if err != nil {
		return webauthn.Assertion{}, err
	}
	return webauthn.Assertion{
		CredentialID:      id,
		ClientDataJSON:    cd,
		AuthenticatorData: ad,
		DERSignature:      sig,
	}, nil
}

func parseAndVerifyPrevout(raw string) (*psbt.Packet, *wire.MsgTx, error) {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(raw), true)
	if err != nil {
		return nil, nil, fmt.Errorf("psbt: %w", err)
	}
	prev, err := vault.RequireVerifiedPrevout(ptx)
	if err != nil {
		return nil, nil, err
	}
	return ptx, prev, nil
}

func verifyDirectAuth(directPub, digest, compact []byte) error {
	pub, err := webauthn.ParseCompressedP256(directPub)
	if err != nil {
		return fmt.Errorf("direct p256: %w", err)
	}
	if err := webauthn.VerifyDigestLowS(pub, digest, compact); err != nil {
		return fmt.Errorf("direct auth: %w", err)
	}
	return nil
}

func rejectPRF(clientDataJSON []byte) error {
	if webauthn.ContainsPRFField(clientDataJSON) {
		return fmt.Errorf("prf material rejected")
	}
	return nil
}

func decodeHex(s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("empty")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("hex: %w", err)
	}
	return b, nil
}

func redact(s string) string {
	if strings.Contains(strings.ToLower(s), "prf") {
		return "[redacted]"
	}
	return s
}

func init() {
	log.SetFlags(log.LstdFlags)
}
