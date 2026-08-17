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

// Service is the trusted VaultCosigner authorization boundary.
type Service struct {
	Ledger     *policy.Ledger
	Deployment deployment.Config
	// CredentialIntegrityKey authenticates the immutable descriptor stored in
	// the authoritative ledger. Production obtains this key from the VaultCosigner
	// scalar through a domain-separated KDF; regtest uses a public deterministic
	// test key so existing demo deployments retain corruption detection.
	CredentialIntegrityKey []byte
	// EnrollmentTokenHash gates the first and only enrollment. Once a
	// credential exists, the token is never consulted again; only the exact
	// persisted tuple remains idempotent.
	EnrollmentTokenHash       []byte
	PhoneRoutineBIP340        *btcec.PublicKey
	ExternalOwnerWallet       *btcec.PublicKey
	RecoveryKey               *btcec.PublicKey
	VaultCosignerPub          *btcec.PublicKey
	DeprecatedVaultCosigners  []*btcec.PublicKey
	ArkadeCosignerPub         *btcec.PublicKey
	DeprecatedArkadeCosigners []*btcec.PublicKey
	ArkadeCosignerOrigin      string
	ArkadeCosignerVersion     string
	Operational               *vault.Built
	Savings                   *vault.Built
	// VaultSigner is the private VaultCosigner-key stage. ArkadeCosignerSigner
	// is the independent public stage and must never hold the VaultCosigner key.
	VaultSigner          Signer
	ArkadeCosignerSigner Signer
	SignTimeout          time.Duration
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
	PhoneRoutineBIP340  *btcec.PublicKey
	ExternalOwnerWallet *btcec.PublicKey
	RecoveryKey         *btcec.PublicKey
	VaultCosignerBase   *btcec.PublicKey
	ArkadeCosignerBase  *btcec.PublicKey
	Operational         *vault.Built
	Savings             *vault.Built
}

// RegisterRequest is the enrollment payload. All byte fields are hex.
// A second call is accepted only when it matches the already-enrolled
// credential ID, WebAuthn P-256, PhoneDirectP256, and PhoneRoutineBIP340,
// and this process's pinned deployment keys/policy still rebuild the stored
// descriptor.
type RegisterRequest struct {
	CredentialID          string `json:"credentialId"`
	WebAuthnP256          string `json:"webauthnP256"`
	PhoneDirectP256       string `json:"phoneDirectP256"`
	PhoneRoutineBIP340Pub string `json:"phoneRoutineBip340Pub"`
}

func (s *Service) Register(req RegisterRequest) error {
	return s.RegisterWithBootstrap(req, "")
}

// RegisterWithBootstrap requires the deployment bootstrap token only while
// the ledger is unenrolled. Errors never include token material.
func (s *Service) attachLedgerIntegrity() error {
	if s == nil || s.Ledger == nil {
		return fmt.Errorf("ledger required")
	}
	key, err := s.credentialIntegrityKey()
	if err != nil {
		return err
	}
	defer zeroServiceBytes(key)
	return s.Ledger.SetIntegrityKey(key)
}

func (s *Service) RegisterWithBootstrap(req RegisterRequest, bootstrap string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.attachLedgerIntegrity(); err != nil {
		return err
	}
	if err := s.runtimeConfig().Validate(); err != nil {
		return fmt.Errorf("deployment: %w", err)
	}

	id, webauthnP256, phoneDirectP256, phoneRoutine, err := parseRegisterRequest(req, s.PhoneRoutineBIP340)
	if err != nil {
		return err
	}

	existing, err := s.loadVerifiedCredential()
	if err != nil {
		return err
	}
	if existing != nil {
		if err := s.acceptPersistedEnrollment(existing, id, webauthnP256, phoneDirectP256, phoneRoutine); err != nil {
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

	op, sv, err := s.makeTrees(phoneRoutine, phoneDirectP256)
	if err != nil {
		return err
	}
	descriptor := descriptorFromTrees(
		s.runtimeConfig(), id, webauthnP256, phoneDirectP256,
		phoneRoutine, s.ExternalOwnerWallet, s.RecoveryKey,
		s.VaultCosignerPub, s.ArkadeCosignerPub,
		s.ArkadeCosignerOrigin, s.ArkadeCosignerVersion, op, sv,
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
		if err := s.acceptPersistedEnrollment(existing, id, webauthnP256, phoneDirectP256, phoneRoutine); err != nil {
			return err
		}
		s.clearEnrollmentTokenHash()
		return nil
	}
	s.bindRemoteExpected(op)
	s.publishEnrollment(phoneRoutine, op, sv)
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
// publishes trees derived from this process's speculative RecoveryKey/Provider.
func (s *Service) acceptPersistedEnrollment(existing *policy.Credential, id, webauthnP256, phoneDirectP256 []byte, phoneRoutine *btcec.PublicKey) error {
	if !sameEnrollmentTuple(existing, id, webauthnP256, phoneDirectP256, phoneRoutine) {
		return fmt.Errorf("enrollment locked")
	}
	return s.publishStoredEnrollment(existing, false)
}

func parseRegisterRequest(req RegisterRequest, fallbackPhoneRoutine *btcec.PublicKey) (id, webauthnP256, phoneDirectP256 []byte, phoneRoutine *btcec.PublicKey, err error) {
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
	phoneDirectP256, err = decodeHex(req.PhoneDirectP256)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("phoneDirectP256: %w", err)
	}
	if _, err = webauthn.ParseCompressedP256(phoneDirectP256); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("phoneDirectP256: %w", err)
	}
	if bytes.Equal(webauthnP256, phoneDirectP256) {
		return nil, nil, nil, nil, fmt.Errorf("direct-auth p256 must be distinct from the webauthn credential p256")
	}
	phoneRoutine, err = parsePhoneRoutineBIP340Pub(req.PhoneRoutineBIP340Pub, fallbackPhoneRoutine)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return id, webauthnP256, phoneDirectP256, phoneRoutine, nil
}

func sameEnrollmentTuple(c *policy.Credential, id, webauthnP256, phoneDirectP256 []byte, phoneRoutine *btcec.PublicKey) bool {
	return c != nil && phoneRoutine != nil &&
		bytes.Equal(c.ID, id) &&
		bytes.Equal(c.WebAuthnP256, webauthnP256) &&
		bytes.Equal(c.PhoneDirectP256, phoneDirectP256) &&
		bytes.Equal(c.PhoneRoutineBIP340, phoneRoutine.SerializeCompressed())
}

// LoadVaults rebuilds trees from the persisted enrollment descriptor.
// Runtime config must be compatible; trees are never derived from a
// rotated GetInfo key or a changed CSV/network/template.
func (s *Service) LoadVaults() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.attachLedgerIntegrity(); err != nil {
		return err
	}
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
	phoneRoutine, externalOwner, recovery, vaultBase, arkadeBase, op, sv, err := s.rebuildFromCredential(cred)
	if err != nil {
		return err
	}
	runtimeVaultCosigner := s.VaultCosignerPub
	// Startup may replace a deprecated/current RemoteSigner identity with the
	// persisted vault identity after compatibility is checked. An idempotent
	// /register never rewrites fields read by concurrent requests.
	if startup {
		s.ExternalOwnerWallet = externalOwner
		s.RecoveryKey = recovery
		s.VaultCosignerPub = vaultBase
		s.ArkadeCosignerPub = arkadeBase
	}
	s.bindRemoteExpected(op)
	s.publishEnrollment(phoneRoutine, op, sv)
	if runtimeVaultCosigner != nil && !sameCompressed(runtimeVaultCosigner, cred.VaultCosignerBase) {
		log.Printf("rebuilt vault from enrolled VaultCosigner base %x; current runtime signer %x must remain deprecated",
			cred.VaultCosignerBase, runtimeVaultCosigner.SerializeCompressed())
	}
	return nil
}

func (s *Service) rebuildFromCredential(cred *policy.Credential) (
	phoneRoutine, externalOwner, recovery, vaultBase, arkadeBase *btcec.PublicKey,
	op, sv *vault.Built, err error,
) {
	if err = s.requireCompatible(cred); err != nil {
		return nil, nil, nil, nil, nil, nil, nil, err
	}
	phoneRoutine, err = btcec.ParsePubKey(cred.PhoneRoutineBIP340)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("stored PhoneRoutineBIP340: %w", err)
	}
	externalOwner, err = btcec.ParsePubKey(cred.ExternalOwnerWallet)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("stored ExternalOwnerWallet: %w", err)
	}
	recovery, err = btcec.ParsePubKey(cred.RecoveryKey)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("stored RecoveryKey: %w", err)
	}
	vaultBase, err = btcec.ParsePubKey(cred.VaultCosignerBase)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("stored VaultCosigner: %w", err)
	}
	arkadeBase, err = btcec.ParsePubKey(cred.ArkadeCosignerBase)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("stored ArkadeCosigner: %w", err)
	}
	opCSV := arklib.RelativeLocktime{Type: arklib.RelativeLocktimeType(cred.OperationalCSVType), Value: cred.OperationalCSVValue}
	svCSV := arklib.RelativeLocktime{Type: arklib.RelativeLocktimeType(cred.SavingsCSVType), Value: cred.SavingsCSVValue}
	op, err = vault.NewFromRecord(vault.Record{
		Kind:                vault.Operational,
		PhoneRoutineBIP340:  phoneRoutine,
		PhoneDirectP256:     cred.PhoneDirectP256,
		ExternalOwnerWallet: externalOwner,
		RecoveryKey:         recovery,
		VaultCosignerBase:   vaultBase,
		ArkadeCosignerBase:  arkadeBase,
		CSV:                 opCSV,
		AuthorizationPolicy: authorizationPolicyFromCredential(cred),
		Network:             cred.Network,
	})
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, err
	}
	sv, err = vault.NewFromRecord(vault.Record{
		Kind:                vault.Savings,
		ExternalOwnerWallet: externalOwner,
		RecoveryKey:         recovery,
		CSV:                 svCSV,
		Network:             cred.Network,
	})
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, err
	}
	if err = sv.AssertNoRoutineCosigners(vaultBase, op.TweakedVaultCosigner, arkadeBase, op.TweakedArkadeCosigner); err != nil {
		return nil, nil, nil, nil, nil, nil, nil, err
	}
	if op.Address != cred.OperationalAddress || !bytes.Equal(op.PkScript, cred.OperationalScript) {
		return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("rebuilt operational vault does not match stored descriptor")
	}
	if sv.Address != cred.SavingsAddress || !bytes.Equal(sv.PkScript, cred.SavingsScript) {
		return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("rebuilt savings vault does not match stored descriptor")
	}
	if op.TweakedVaultCosigner == nil || !bytes.Equal(op.TweakedVaultCosigner.SerializeCompressed(), cred.TweakedVaultCosigner) {
		return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("rebuilt tweaked VaultCosigner does not match stored descriptor")
	}
	if op.TweakedArkadeCosigner == nil || !bytes.Equal(op.TweakedArkadeCosigner.SerializeCompressed(), cred.TweakedArkadeCosigner) {
		return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("rebuilt tweaked ArkadeCosigner does not match stored descriptor")
	}
	return phoneRoutine, externalOwner, recovery, vaultBase, arkadeBase, op, sv, nil
}

func (s *Service) makeTrees(phoneRoutine *btcec.PublicKey, phoneDirectP256 []byte) (*vault.Built, *vault.Built, error) {
	if phoneRoutine == nil || s.ExternalOwnerWallet == nil || s.RecoveryKey == nil || s.VaultCosignerPub == nil || s.ArkadeCosignerPub == nil {
		return nil, nil, fmt.Errorf("vault keys not configured")
	}
	cfg := s.runtimeConfig()
	opCSV := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: cfg.OperationalCSVBlocks}
	svCSV := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: cfg.SavingsCSVBlocks}
	op, err := vault.NewOperationalWithPolicy(vault.OperationalKeys{
		PhoneRoutineBIP340:  phoneRoutine,
		PhoneDirectP256:     phoneDirectP256,
		ExternalOwnerWallet: s.ExternalOwnerWallet,
		RecoveryKey:         s.RecoveryKey,
		VaultCosignerBase:   s.VaultCosignerPub,
		ArkadeCosignerBase:  s.ArkadeCosignerPub,
	}, cfg.Network, opCSV, configuredAuthorizationPolicy())
	if err != nil {
		return nil, nil, err
	}
	sv, err := vault.NewSavingsWithPolicy(
		s.ExternalOwnerWallet, s.RecoveryKey, cfg.Network, svCSV,
		s.VaultCosignerPub, op.TweakedVaultCosigner, s.ArkadeCosignerPub, op.TweakedArkadeCosigner,
	)
	if err != nil {
		return nil, nil, err
	}
	return op, sv, nil
}

func descriptorFromTrees(
	cfg deployment.Config, id, webauthnP256, phoneDirectP256 []byte,
	phoneRoutine, externalOwner, recovery, vaultBase, arkadeBase *btcec.PublicKey,
	arkadeOrigin, arkadeVersion string, op, sv *vault.Built,
) policy.Credential {
	opCSV := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: cfg.OperationalCSVBlocks}
	svCSV := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: cfg.SavingsCSVBlocks}
	return policy.Credential{
		ID:                    id,
		WebAuthnP256:          append([]byte(nil), webauthnP256...),
		PhoneDirectP256:       append([]byte(nil), phoneDirectP256...),
		PhoneRoutineBIP340:    phoneRoutine.SerializeCompressed(),
		ExternalOwnerWallet:   externalOwner.SerializeCompressed(),
		RPID:                  cfg.RPID,
		Origin:                cfg.ClientOrigin,
		RecoveryKey:           recovery.SerializeCompressed(),
		VaultCosignerBase:     vaultBase.SerializeCompressed(),
		TweakedVaultCosigner:  op.TweakedVaultCosigner.SerializeCompressed(),
		ArkadeCosignerBase:    arkadeBase.SerializeCompressed(),
		TweakedArkadeCosigner: op.TweakedArkadeCosigner.SerializeCompressed(),
		ArkadeCosignerOrigin:  arkadeOrigin,
		ArkadeCosignerVersion: arkadeVersion,
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
	if cred.ArkadeCosignerOrigin != s.ArkadeCosignerOrigin {
		return fmt.Errorf("stored ArkadeCosigner origin %q incompatible with runtime %q", cred.ArkadeCosignerOrigin, s.ArkadeCosignerOrigin)
	}
	if cfg.Network != deployment.NetworkRegtest && (cred.ArkadeCosignerVersion == "" || s.ArkadeCosignerVersion == "") {
		return fmt.Errorf("stored and runtime ArkadeCosigner versions are required")
	}
	// The persisted value records the exact reviewed version at enrollment.
	// Runtime separately accepts only its release allowlist. They need not be
	// equal after a reviewed key/version rotation: an existing descriptor stays
	// live only when its exact MAC-authenticated key is still advertised as an
	// active deprecated signer.
	if s.ExternalOwnerWallet != nil && !sameCompressed(s.ExternalOwnerWallet, cred.ExternalOwnerWallet) {
		return fmt.Errorf("runtime ExternalOwnerWallet does not match enrolled vault")
	}
	if s.RecoveryKey != nil && !sameCompressed(s.RecoveryKey, cred.RecoveryKey) {
		return fmt.Errorf("runtime RecoveryKey does not match enrolled vault")
	}
	if err := requireSignerCompatible("VaultCosigner", s.VaultCosignerPub, s.DeprecatedVaultCosigners, cred.VaultCosignerBase); err != nil {
		return err
	}
	if err := requireSignerCompatible("ArkadeCosigner", s.ArkadeCosignerPub, s.DeprecatedArkadeCosigners, cred.ArkadeCosignerBase); err != nil {
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
	if binder, ok := s.VaultSigner.(interface{ BindExpectedSigner([]byte) }); ok && op.TweakedVaultCosigner != nil {
		binder.BindExpectedSigner(schnorr.SerializePubKey(op.TweakedVaultCosigner))
	}
	if binder, ok := s.ArkadeCosignerSigner.(interface{ BindExpectedSigner([]byte) }); ok && op.TweakedArkadeCosigner != nil {
		binder.BindExpectedSigner(schnorr.SerializePubKey(op.TweakedArkadeCosigner))
	}
}

func parsePhoneRoutineBIP340Pub(hexPub string, fallback *btcec.PublicKey) (*btcec.PublicKey, error) {
	if hexPub == "" {
		if fallback == nil {
			return nil, fmt.Errorf("phoneRoutineBip340Pub required")
		}
		return fallback, nil
	}
	raw, err := decodeHex(hexPub)
	if err != nil {
		return nil, fmt.Errorf("phoneRoutineBip340Pub: %w", err)
	}
	pub, err := btcec.ParsePubKey(raw)
	if err != nil {
		return nil, fmt.Errorf("phoneRoutineBip340Pub: %w", err)
	}
	return pub, nil
}

// Status is the UI snapshot.
type Status struct {
	Enrolled                        bool   `json:"enrolled"`
	Network                         string `json:"network"`
	ClientOrigin                    string `json:"clientOrigin"`
	RPID                            string `json:"rpId"`
	VaultID                         string `json:"vaultId"`
	TemplateVersion                 string `json:"templateVersion"`
	PolicyVersion                   string `json:"policyVersion"`
	OperationalCSVBlocks            uint32 `json:"operationalCsvBlocks"`
	SavingsCSVBlocks                uint32 `json:"savingsCsvBlocks"`
	ExternalOwnerWalletPub          string `json:"externalOwnerWalletPub,omitempty"`
	RecoveryKeyPub                  string `json:"recoveryKeyPub,omitempty"`
	VaultCosignerBasePub            string `json:"vaultCosignerBasePub,omitempty"`
	ArkadeCosignerBasePub           string `json:"arkadeCosignerBasePub,omitempty"`
	ArkadeCosignerOrigin            string `json:"arkadeCosignerOrigin,omitempty"`
	ArkadeCosignerVersion           string `json:"arkadeCosignerVersion,omitempty"`
	OperationalAddr                 string `json:"operationalAddress"`
	OperationalScript               string `json:"operationalScript,omitempty"`
	SavingsAddr                     string `json:"savingsAddress"`
	SavingsExcludesRoutineCosigners bool   `json:"savingsExcludesRoutineCosigners"`
	PeriodAllowance                 int64  `json:"periodAllowance"`
	PeriodSpent                     int64  `json:"periodSpent"`
	PeriodRemaining                 int64  `json:"periodRemaining"`
	TxCap                           int64  `json:"txCap"`
	AbsoluteFeeCap                  int64  `json:"absoluteFeeCap"`
	FeerateCapSatPerV               int64  `json:"feerateCapSatVb"`
	PhoneRoutineBIP340Pub           string `json:"phoneRoutineBip340Pub,omitempty"`
	PhoneDirectP256                 string `json:"phoneDirectP256,omitempty"`
	TweakedVaultCosignerXOnly       string `json:"tweakedVaultCosignerXOnly,omitempty"`
	TweakedArkadeCosignerXOnly      string `json:"tweakedArkadeCosignerXOnly,omitempty"`
}

func (s *Service) publishEnrollment(phoneRoutine *btcec.PublicKey, op, sv *vault.Built) {
	snap := &enrolledSnapshot{PhoneRoutineBIP340: phoneRoutine, Operational: op, Savings: sv}
	if op != nil {
		snap.ExternalOwnerWallet = op.Record.ExternalOwnerWallet
		snap.RecoveryKey = op.Record.RecoveryKey
		snap.VaultCosignerBase = op.Record.VaultCosignerBase
		snap.ArkadeCosignerBase = op.Record.ArkadeCosignerBase
	}
	s.published.Store(snap)
	// Keep exported legacy/test fields stable after their first publication.
	if s.PhoneRoutineBIP340 == nil {
		s.PhoneRoutineBIP340 = phoneRoutine
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
	if err := s.attachLedgerIntegrity(); err != nil {
		return Status{}, err
	}
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
		if s.ExternalOwnerWallet != nil {
			st.ExternalOwnerWalletPub = hex.EncodeToString(s.ExternalOwnerWallet.SerializeCompressed())
		}
		if s.RecoveryKey != nil {
			st.RecoveryKeyPub = hex.EncodeToString(s.RecoveryKey.SerializeCompressed())
		}
		if s.VaultCosignerPub != nil {
			st.VaultCosignerBasePub = hex.EncodeToString(s.VaultCosignerPub.SerializeCompressed())
		}
		if s.ArkadeCosignerPub != nil {
			st.ArkadeCosignerBasePub = hex.EncodeToString(s.ArkadeCosignerPub.SerializeCompressed())
		}
	}
	if cred != nil {
		// Report the persisted descriptor inputs, not merely mutable runtime
		// fields. LoadVaults/Register already require these to match runtime.
		st.ExternalOwnerWalletPub = hex.EncodeToString(cred.ExternalOwnerWallet)
		st.RecoveryKeyPub = hex.EncodeToString(cred.RecoveryKey)
		st.VaultCosignerBasePub = hex.EncodeToString(cred.VaultCosignerBase)
		st.ArkadeCosignerBasePub = hex.EncodeToString(cred.ArkadeCosignerBase)
		st.ArkadeCosignerOrigin = cred.ArkadeCosignerOrigin
		st.ArkadeCosignerVersion = cred.ArkadeCosignerVersion
	}
	if snap.Operational != nil {
		st.OperationalAddr = snap.Operational.Address
		st.OperationalScript = hex.EncodeToString(snap.Operational.PkScript)
		if snap.Operational.TweakedVaultCosigner != nil {
			st.TweakedVaultCosignerXOnly = hex.EncodeToString(schnorr.SerializePubKey(snap.Operational.TweakedVaultCosigner))
		}
		if snap.Operational.TweakedArkadeCosigner != nil {
			st.TweakedArkadeCosignerXOnly = hex.EncodeToString(schnorr.SerializePubKey(snap.Operational.TweakedArkadeCosigner))
		}
	}
	if snap.Savings != nil {
		st.SavingsAddr = snap.Savings.Address
		var forbidden []*btcec.PublicKey
		if snap.VaultCosignerBase != nil {
			forbidden = append(forbidden, snap.VaultCosignerBase)
		}
		if snap.Operational != nil && snap.Operational.TweakedVaultCosigner != nil {
			forbidden = append(forbidden, snap.Operational.TweakedVaultCosigner)
		}
		if snap.ArkadeCosignerBase != nil {
			forbidden = append(forbidden, snap.ArkadeCosignerBase)
		}
		if snap.Operational != nil && snap.Operational.TweakedArkadeCosigner != nil {
			forbidden = append(forbidden, snap.Operational.TweakedArkadeCosigner)
		}
		st.SavingsExcludesRoutineCosigners = snap.Savings.AssertNoRoutineCosigners(forbidden...) == nil
	}
	if snap.PhoneRoutineBIP340 != nil {
		st.PhoneRoutineBIP340Pub = hex.EncodeToString(snap.PhoneRoutineBIP340.SerializeCompressed())
	}
	if cred != nil && len(cred.PhoneDirectP256) > 0 {
		st.PhoneDirectP256 = hex.EncodeToString(cred.PhoneDirectP256)
	}
	return st, nil
}

// DraftRequest builds an empty-witness routine PSBT the browser can bind.
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
	built, err := vault.BuildRoutineSpend(vault.SpendParams{
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
	if err := verifyDirectAuth(cred.PhoneDirectP256, ch, directSig); err != nil {
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
	if err := s.attachLedgerIntegrity(); err != nil {
		return "", false, err
	}
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
	if s.VaultSigner == nil || s.ArkadeCosignerSigner == nil || op.TweakedVaultCosigner == nil || op.TweakedArkadeCosigner == nil {
		return "", false, fmt.Errorf("both VaultCosigner and ArkadeCosigner signers are required")
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
				signCtx, storedRequest, s.VaultSigner,
				schnorr.SerializePubKey(op.TweakedVaultCosigner), "VaultCosigner",
			)
		},
		func(issueCtx context.Context, storedVaultPSBT string) (string, error) {
			if err := issueCtx.Err(); err != nil {
				return "", err
			}
			vaultStage, _, err := parseAndVerifyPrevout(storedVaultPSBT)
			if err != nil {
				return "", fmt.Errorf("stored VaultCosigner stage: %w", err)
			}
			if err := verifyExactRoutineSignatures(
				vaultStage, op, op.Record.PhoneRoutineBIP340, op.TweakedVaultCosigner,
			); err != nil {
				return "", fmt.Errorf("stored VaultCosigner stage: %w", err)
			}
			signCtx, cancel := context.WithTimeout(issueCtx, timeout)
			defer cancel()
			completed, err := signExactStage(
				signCtx, storedVaultPSBT, s.ArkadeCosignerSigner,
				schnorr.SerializePubKey(op.TweakedArkadeCosigner), "ArkadeCosigner",
			)
			if err != nil {
				return "", err
			}
			completedPacket, _, err := parseAndVerifyPrevout(completed)
			if err != nil {
				return "", err
			}
			if err := verifyExactRoutineSignatures(
				completedPacket, op, op.Record.PhoneRoutineBIP340, op.TweakedVaultCosigner, op.TweakedArkadeCosigner,
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
	verified, err := webauthn.Validate(assertion, webauthn.Expected{
		CredentialID: cred.ID,
		WebAuthnP256: cred.WebAuthnP256,
		Challenge:    challenge,
		Origin:       cred.Origin,
		RPID:         cred.RPID,
	})
	if err != nil {
		return nil, err
	}
	key, err := s.credentialIntegrityKey()
	if err != nil {
		return nil, err
	}
	defer zeroServiceBytes(key)
	if err := s.Ledger.UpdateWebAuthnSignCount(cred, verified.SignCount, key); err != nil {
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
	if err := verifyDirectAuth(cred.PhoneDirectP256, challenge, packet[0].Witness[0]); err != nil {
		return nil, err
	}
	if err := verifyPhoneRoutineSignature(ptx, op); err != nil {
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
	lower := strings.ToLower(s)
	if strings.Contains(lower, "prf") || strings.Contains(lower, "token") || strings.Contains(lower, "scalar") {
		return "[redacted]"
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func init() {
	log.SetFlags(log.LstdFlags)
}
