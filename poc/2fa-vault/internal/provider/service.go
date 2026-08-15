package provider

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/emulator/poc/2fa-vault/fixture"
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
	Ledger             *policy.Ledger
	Hot                *btcec.PublicKey
	Offline            *btcec.PublicKey
	ProviderPub        *btcec.PublicKey
	DeprecatedProvider []*btcec.PublicKey
	Operational        *vault.Built
	Savings            *vault.Built
	Signer             Signer
	SignTimeout        time.Duration
	Broadcaster        Broadcaster
	mu                 sync.Mutex
	published          atomic.Pointer[enrolledSnapshot]
}

// enrolledSnapshot is one immutable published enrollment. Register and
// LoadVaults store a single pointer; readers load that pointer only.
type enrolledSnapshot struct {
	Hot         *btcec.PublicKey
	Operational *vault.Built
	Savings     *vault.Built
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
	s.mu.Lock()
	defer s.mu.Unlock()

	id, webauthnP256, directP256, hot, err := parseRegisterRequest(req, s.Hot)
	if err != nil {
		return err
	}

	existing, err := s.Ledger.GetCredential()
	if err != nil {
		return err
	}
	if existing != nil {
		return s.acceptPersistedEnrollment(existing, id, webauthnP256, directP256, hot)
	}

	op, sv, err := s.makeTrees(hot, directP256)
	if err != nil {
		return err
	}
	if err := s.Ledger.Enroll(descriptorFromTrees(id, webauthnP256, directP256, hot, s.Offline, s.ProviderPub, op, sv)); err != nil {
		existing, getErr := s.Ledger.GetCredential()
		if getErr != nil {
			return err
		}
		if existing == nil {
			return err
		}
		return s.acceptPersistedEnrollment(existing, id, webauthnP256, directP256, hot)
	}
	s.bindRemoteExpected(op)
	s.publishEnrollment(hot, op, sv)
	return nil
}

// acceptPersistedEnrollment succeeds only for the exact user tuple when
// runtime config matches the stored descriptor and trees rebuilt from that
// record equal the persisted addresses/scripts/tweaked provider. It never
// publishes trees derived from this process's speculative Offline/Provider.
func (s *Service) acceptPersistedEnrollment(existing *policy.Credential, id, webauthnP256, directP256 []byte, hot *btcec.PublicKey) error {
	if !sameEnrollmentTuple(existing, id, webauthnP256, directP256, hot) {
		return fmt.Errorf("enrollment locked")
	}
	return s.publishStoredEnrollment(existing)
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
	cred, err := s.Ledger.GetCredential()
	if err != nil {
		return err
	}
	if cred == nil {
		return nil
	}
	return s.publishStoredEnrollment(cred)
}

func (s *Service) publishStoredEnrollment(cred *policy.Credential) error {
	hot, offline, providerBase, op, sv, err := s.rebuildFromCredential(cred)
	if err != nil {
		return err
	}
	runtimeProvider := s.ProviderPub
	s.Offline = offline
	s.ProviderPub = providerBase
	s.bindRemoteExpected(op)
	s.publishEnrollment(hot, op, sv)
	if runtimeProvider != nil && !sameCompressed(runtimeProvider, cred.ProviderBase) {
		log.Printf("rebuilt vault from enrolled provider base %x; current emulator signer %x must remain deprecated",
			cred.ProviderBase, runtimeProvider.SerializeCompressed())
	}
	return nil
}

func (s *Service) rebuildFromCredential(cred *policy.Credential) (hot, offline, providerBase *btcec.PublicKey, op, sv *vault.Built, err error) {
	if err = s.requireCompatible(cred); err != nil {
		return nil, nil, nil, nil, nil, err
	}
	hot, err = btcec.ParsePubKey(cred.Hot)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("stored hot: %w", err)
	}
	offline, err = btcec.ParsePubKey(cred.Offline)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("stored offline: %w", err)
	}
	providerBase, err = btcec.ParsePubKey(cred.ProviderBase)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("stored provider: %w", err)
	}
	opCSV := arklib.RelativeLocktime{Type: arklib.RelativeLocktimeType(cred.OperationalCSVType), Value: cred.OperationalCSVValue}
	svCSV := arklib.RelativeLocktime{Type: arklib.RelativeLocktimeType(cred.SavingsCSVType), Value: cred.SavingsCSVValue}
	op, err = vault.NewFromRecord(vault.Record{
		Kind:         vault.Operational,
		Hot:          hot,
		Offline:      offline,
		ProviderBase: providerBase,
		DirectP256:   cred.DirectP256,
		CSV:          opCSV,
		Network:      cred.Network,
	})
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	sv, err = vault.NewFromRecord(vault.Record{
		Kind:    vault.Savings,
		Hot:     hot,
		Offline: offline,
		CSV:     svCSV,
		Network: cred.Network,
	})
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	if err = sv.AssertNoProvider(providerBase, op.TweakedProvider); err != nil {
		return nil, nil, nil, nil, nil, err
	}
	if op.Address != cred.OperationalAddress || !bytes.Equal(op.PkScript, cred.OperationalScript) {
		return nil, nil, nil, nil, nil, fmt.Errorf("rebuilt operational vault does not match stored descriptor")
	}
	if sv.Address != cred.SavingsAddress || !bytes.Equal(sv.PkScript, cred.SavingsScript) {
		return nil, nil, nil, nil, nil, fmt.Errorf("rebuilt savings vault does not match stored descriptor")
	}
	if op.TweakedProvider == nil || !bytes.Equal(op.TweakedProvider.SerializeCompressed(), cred.TweakedProvider) {
		return nil, nil, nil, nil, nil, fmt.Errorf("rebuilt tweaked provider does not match stored descriptor")
	}
	return hot, offline, providerBase, op, sv, nil
}

func (s *Service) makeTrees(hot *btcec.PublicKey, directP256 []byte) (*vault.Built, *vault.Built, error) {
	if hot == nil || s.Offline == nil || s.ProviderPub == nil {
		return nil, nil, fmt.Errorf("vault keys not configured")
	}
	op, err := vault.NewOperational(hot, s.Offline, s.ProviderPub, directP256)
	if err != nil {
		return nil, nil, err
	}
	sv, err := vault.NewSavings(hot, s.Offline, s.ProviderPub, op.TweakedProvider)
	if err != nil {
		return nil, nil, err
	}
	return op, sv, nil
}

func descriptorFromTrees(id, webauthnP256, directP256 []byte, hot, offline, providerBase *btcec.PublicKey, op, sv *vault.Built) policy.Credential {
	opCSV := fixture.OperationalCSV()
	svCSV := fixture.SavingsCSV()
	return policy.Credential{
		ID:                  id,
		WebAuthnP256:        append([]byte(nil), webauthnP256...),
		DirectP256:          append([]byte(nil), directP256...),
		Hot:                 hot.SerializeCompressed(),
		RPID:                fixture.RPID,
		Origin:              fixture.Origin,
		Offline:             offline.SerializeCompressed(),
		ProviderBase:        providerBase.SerializeCompressed(),
		TweakedProvider:     op.TweakedProvider.SerializeCompressed(),
		TemplateVersion:     fixture.TemplateVersion,
		PolicyVersion:       fixture.PolicyVersion,
		Network:             fixture.Network,
		VaultID:             fixture.VaultID,
		OperationalCSVType:  int64(opCSV.Type),
		OperationalCSVValue: opCSV.Value,
		SavingsCSVType:      int64(svCSV.Type),
		SavingsCSVValue:     svCSV.Value,
		OperationalAddress:  op.Address,
		OperationalScript:   append([]byte(nil), op.PkScript...),
		SavingsAddress:      sv.Address,
		SavingsScript:       append([]byte(nil), sv.PkScript...),
	}
}

func (s *Service) requireCompatible(cred *policy.Credential) error {
	if cred.TemplateVersion != fixture.TemplateVersion {
		return fmt.Errorf("stored template %q incompatible with runtime %q", cred.TemplateVersion, fixture.TemplateVersion)
	}
	if cred.PolicyVersion != fixture.PolicyVersion {
		return fmt.Errorf("stored policy %q incompatible with runtime %q", cred.PolicyVersion, fixture.PolicyVersion)
	}
	if cred.Network != fixture.Network {
		return fmt.Errorf("stored network %q incompatible with runtime %q", cred.Network, fixture.Network)
	}
	if cred.VaultID != fixture.VaultID {
		return fmt.Errorf("stored vault id %q incompatible with runtime %q", cred.VaultID, fixture.VaultID)
	}
	opCSV := fixture.OperationalCSV()
	svCSV := fixture.SavingsCSV()
	if cred.OperationalCSVType != int64(opCSV.Type) || cred.OperationalCSVValue != opCSV.Value {
		return fmt.Errorf("stored operational CSV incompatible with runtime")
	}
	if cred.SavingsCSVType != int64(svCSV.Type) || cred.SavingsCSVValue != svCSV.Value {
		return fmt.Errorf("stored savings CSV incompatible with runtime")
	}
	if cred.Origin != fixture.Origin {
		return fmt.Errorf("stored origin %q incompatible with runtime %q", cred.Origin, fixture.Origin)
	}
	if cred.RPID != fixture.RPID {
		return fmt.Errorf("stored rp id %q incompatible with runtime %q", cred.RPID, fixture.RPID)
	}
	if s.Offline != nil && !sameCompressed(s.Offline, cred.Offline) {
		return fmt.Errorf("runtime offline pubkey does not match enrolled vault")
	}
	if err := s.requireProviderCompatible(cred.ProviderBase); err != nil {
		return err
	}
	return nil
}

func (s *Service) requireProviderCompatible(stored []byte) error {
	if s.ProviderPub == nil && len(s.DeprecatedProvider) == 0 {
		return nil
	}
	if s.ProviderPub != nil && sameCompressed(s.ProviderPub, stored) {
		return nil
	}
	for _, pub := range s.DeprecatedProvider {
		if sameCompressed(pub, stored) {
			return nil
		}
	}
	return fmt.Errorf("enrolled provider key is not the current emulator signer and is not listed as deprecated")
}

func sameCompressed(pub *btcec.PublicKey, raw []byte) bool {
	return pub != nil && bytes.Equal(pub.SerializeCompressed(), raw)
}

func (s *Service) bindRemoteExpected(op *vault.Built) {
	if rs, ok := s.Signer.(*RemoteSigner); ok && op != nil && op.TweakedProvider != nil {
		rs.ExpectedXOnly = schnorr.SerializePubKey(op.TweakedProvider)
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
	Enrolled                bool   `json:"enrolled"`
	OperationalAddr         string `json:"operationalAddress"`
	OperationalScript       string `json:"operationalScript,omitempty"`
	SavingsAddr             string `json:"savingsAddress"`
	SavingsExcludesProvider bool   `json:"savingsExcludesProvider"`
	PeriodAllowance         int64  `json:"periodAllowance"`
	PeriodSpent             int64  `json:"periodSpent"`
	PeriodRemaining         int64  `json:"periodRemaining"`
	TxCap                   int64  `json:"txCap"`
	HotPub                  string `json:"hotPub,omitempty"`
	DirectP256              string `json:"directP256,omitempty"`
	TweakedProviderXOnly    string `json:"tweakedProviderXOnly,omitempty"`
}

func (s *Service) publishEnrollment(hot *btcec.PublicKey, op, sv *vault.Built) {
	s.published.Store(&enrolledSnapshot{Hot: hot, Operational: op, Savings: sv})
	s.Hot = hot
	s.Operational = op
	s.Savings = sv
}

func (s *Service) enrolled() enrolledSnapshot {
	if snap := s.published.Load(); snap != nil {
		return *snap
	}
	return enrolledSnapshot{}
}

func (s *Service) Status(ctx context.Context) (Status, error) {
	cred, err := s.Ledger.GetCredential()
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
		Enrolled:        cred != nil,
		PeriodAllowance: fixture.PeriodAllowanceSats,
		PeriodSpent:     spent,
		PeriodRemaining: rem,
		TxCap:           fixture.TxRecipientCapSats,
	}
	snap := s.enrolled()
	if snap.Operational != nil {
		st.OperationalAddr = snap.Operational.Address
		st.OperationalScript = hex.EncodeToString(snap.Operational.PkScript)
		if snap.Operational.TweakedProvider != nil {
			st.TweakedProviderXOnly = hex.EncodeToString(schnorr.SerializePubKey(snap.Operational.TweakedProvider))
		}
	}
	if snap.Savings != nil {
		st.SavingsAddr = snap.Savings.Address
		var forbidden []*btcec.PublicKey
		if s.ProviderPub != nil {
			forbidden = append(forbidden, s.ProviderPub)
		}
		if snap.Operational != nil && snap.Operational.TweakedProvider != nil {
			forbidden = append(forbidden, snap.Operational.TweakedProvider)
		}
		st.SavingsExcludesProvider = snap.Savings.AssertNoProvider(forbidden...) == nil
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
	op := s.enrolled().Operational
	if op == nil {
		return "", fmt.Errorf("not enrolled")
	}
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
	op := s.enrolled().Operational
	if op == nil {
		return "", fmt.Errorf("not enrolled")
	}
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
	cred, err := s.Ledger.GetCredential()
	if err != nil || cred == nil {
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
	op := s.enrolled().Operational
	if op == nil {
		return nil, fmt.Errorf("not enrolled")
	}
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
	ptx, _, err := parseAndVerifyPrevout(req.PSBT)
	if err != nil {
		return "", false, err
	}
	cl, err := classifySpend(ptx, op)
	if err != nil {
		return "", false, err
	}

	assertion, err := decodeAssertion(req)
	if err != nil {
		return "", false, err
	}
	if err := rejectPRF(assertion.ClientDataJSON); err != nil {
		return "", false, err
	}
	cred, err := s.Ledger.GetCredential()
	if err != nil {
		return "", false, err
	}
	if cred == nil {
		return "", false, fmt.Errorf("not enrolled")
	}

	challenge, err := vault.Challenge(ptx, op)
	if err != nil {
		return "", false, err
	}
	if _, err := webauthn.Validate(assertion, webauthn.Expected{
		CredentialID: cred.ID,
		WebAuthnP256: cred.WebAuthnP256,
		Challenge:    challenge,
		Origin:       cred.Origin,
		RPID:         cred.RPID,
	}); err != nil {
		return "", false, err
	}

	packet, err := arkade.FindEmulatorPacket(ptx.UnsignedTx)
	if err != nil {
		return "", false, err
	}
	if len(packet) != 1 {
		return "", false, fmt.Errorf("emulator packet")
	}
	if len(packet[0].Witness) != 1 || len(packet[0].Witness[0]) != 64 {
		return "", false, fmt.Errorf("packet witness must be the one-item 64-byte direct signature")
	}
	if err := verifyDirectAuth(cred.DirectP256, challenge, packet[0].Witness[0]); err != nil {
		return "", false, err
	}
	if err := verifyHotSignature(ptx, op); err != nil {
		return "", false, err
	}

	timeout := s.SignTimeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}

	return s.Ledger.Issue(ctx, fixture.VaultID, challenge, cl.Recipient.Value, cl.Fee, fixture.PeriodAllowanceSats,
		func(issueCtx context.Context) (string, error) {
			if err := issueCtx.Err(); err != nil {
				return "", err
			}
			// Start the signing window only after Issue has serialized this
			// caller and committed its reservation. Creating it earlier lets a
			// queued request expire while waiting, then reserve budget and
			// call Sign with a dead context.
			signCtx, cancel := context.WithTimeout(issueCtx, timeout)
			defer cancel()
			signed, err := s.Signer.Sign(signCtx, ptx)
			if err != nil {
				return "", err
			}
			enc, err := signed.B64Encode()
			if err != nil {
				return "", err
			}
			return enc, nil
		},
	)
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
