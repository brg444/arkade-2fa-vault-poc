// Command adminpsbt is a file-only reference handoff for the v4
// PhoneRoutineBIP340+ExternalOwnerWallet admin path. It never opens a listener
// and never reads or produces private key material.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/emulator/poc/2fa-vault/fixture"
	"github.com/arkade-os/emulator/poc/2fa-vault/internal/deployment"
	"github.com/arkade-os/emulator/poc/2fa-vault/internal/vault"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

const maxFileBytes = 4 << 20

type descriptor struct {
	Enrolled                        bool   `json:"enrolled"`
	Network                         string `json:"network"`
	ClientOrigin                    string `json:"clientOrigin"`
	RPID                            string `json:"rpId"`
	VaultID                         string `json:"vaultId"`
	TemplateVersion                 string `json:"templateVersion"`
	PolicyVersion                   string `json:"policyVersion"`
	OperationalCSVBlocks            uint32 `json:"operationalCsvBlocks"`
	SavingsCSVBlocks                uint32 `json:"savingsCsvBlocks"`
	ExternalOwnerWalletPub          string `json:"externalOwnerWalletPub"`
	RecoveryKeyPub                  string `json:"recoveryKeyPub,omitempty"`
	VaultCosignerBasePub            string `json:"vaultCosignerBasePub"`
	ArkadeCosignerBasePub           string `json:"arkadeCosignerBasePub"`
	ArkadeCosignerOrigin            string `json:"arkadeCosignerOrigin"`
	ArkadeCosignerVersion           string `json:"arkadeCosignerVersion"`
	OperationalAddress              string `json:"operationalAddress"`
	OperationalScript               string `json:"operationalScript"`
	SavingsAddress                  string `json:"savingsAddress"`
	SavingsExcludesRoutineCosigners bool   `json:"savingsExcludesRoutineCosigners"`
	PeriodAllowance                 int64  `json:"periodAllowance"`
	PeriodSpent                     int64  `json:"periodSpent"`
	PeriodRemaining                 int64  `json:"periodRemaining"`
	TxCap                           int64  `json:"txCap"`
	AbsoluteFeeCap                  int64  `json:"absoluteFeeCap"`
	FeerateCapSatPerV               int64  `json:"feerateCapSatVb"`
	PhoneRoutineBIP340Pub           string `json:"phoneRoutineBip340Pub"`
	PhoneDirectP256                 string `json:"phoneDirectP256"`
	TweakedVaultCosignerXOnly       string `json:"tweakedVaultCosignerXOnly"`
	TweakedArkadeCosignerXOnly      string `json:"tweakedArkadeCosignerXOnly"`
}

type buildRequest struct {
	PrevTxHex         string `json:"prevTxHex"`
	Vout              uint32 `json:"vout"`
	DestinationScript string `json:"destinationScript"`
	DestinationAmount int64  `json:"destinationAmount"`
	Fee               int64  `json:"fee"`
}

func main() {
	mode := flag.String("mode", "", "build or finalize")
	descriptorPath := flag.String("descriptor", "", "file containing an enrolled /v1/status JSON snapshot")
	requestPath := flag.String("request", "", "build request JSON file")
	psbtPath := flag.String("psbt", "", "externally signed PSBT file (base64)")
	outPath := flag.String("out", "", "output PSBT file")
	txOutPath := flag.String("tx-out", "", "finalize-only output transaction hex file")
	flag.Parse()

	if err := run(*mode, *descriptorPath, *requestPath, *psbtPath, *outPath, *txOutPath); err != nil {
		fmt.Fprintln(os.Stderr, "adminpsbt:", err)
		os.Exit(1)
	}
}

func run(mode, descriptorPath, requestPath, psbtPath, outPath, txOutPath string) error {
	if descriptorPath == "" || outPath == "" {
		return fmt.Errorf("-descriptor and -out are required")
	}
	desc, err := readDescriptor(descriptorPath)
	if err != nil {
		return err
	}
	built, err := desc.buildVault()
	if err != nil {
		return fmt.Errorf("descriptor: %w", err)
	}

	switch mode {
	case "build":
		if requestPath == "" || psbtPath != "" || txOutPath != "" {
			return fmt.Errorf("build requires -request and forbids -psbt/-tx-out")
		}
		req, err := readBuildRequest(requestPath)
		if err != nil {
			return err
		}
		packet, err := buildAdminPSBT(built, req)
		if err != nil {
			return err
		}
		encoded, err := packet.B64Encode()
		if err != nil {
			return err
		}
		return writeExclusive(outPath, []byte(encoded+"\n"))
	case "finalize":
		if psbtPath == "" || txOutPath == "" || requestPath != "" {
			return fmt.Errorf("finalize requires -psbt and -tx-out and forbids -request")
		}
		packet, err := readPSBT(psbtPath)
		if err != nil {
			return err
		}
		if err := vault.FinalizeAdmin(packet, built); err != nil {
			return fmt.Errorf("verify phone+hardware admin signatures: %w", err)
		}
		if err := vault.ExecuteFinalizedAdmin(packet, built); err != nil {
			return fmt.Errorf("execute finalized admin witness: %w", err)
		}
		encoded, err := packet.B64Encode()
		if err != nil {
			return err
		}
		tx, err := vault.ExtractFinalizedTx(packet)
		if err != nil {
			return err
		}
		var raw bytes.Buffer
		if err := tx.Serialize(&raw); err != nil {
			return err
		}
		if err := writeExclusive(outPath, []byte(encoded+"\n")); err != nil {
			return err
		}
		if err := writeExclusive(txOutPath, []byte(hex.EncodeToString(raw.Bytes())+"\n")); err != nil {
			_ = os.Remove(outPath)
			return err
		}
		return nil
	default:
		return fmt.Errorf("-mode must be build or finalize")
	}
}

func readDescriptor(path string) (descriptor, error) {
	var out descriptor
	if err := readJSONFile(path, &out); err != nil {
		return descriptor{}, fmt.Errorf("read descriptor: %w", err)
	}
	return out, nil
}

func readBuildRequest(path string) (buildRequest, error) {
	var out buildRequest
	if err := readJSONFile(path, &out); err != nil {
		return buildRequest{}, fmt.Errorf("read build request: %w", err)
	}
	return out, nil
}

func readJSONFile(path string, target any) error {
	raw, err := readBoundedFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}

func readBoundedFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxFileBytes {
		return nil, fmt.Errorf("file exceeds %d bytes", maxFileBytes)
	}
	return raw, nil
}

func (d descriptor) buildVault() (*vault.Built, error) {
	if !d.Enrolled || d.VaultID != fixture.VaultID {
		return nil, fmt.Errorf("descriptor is not the enrolled %s vault", fixture.VaultID)
	}
	if d.TemplateVersion != fixture.TemplateVersion || d.PolicyVersion != fixture.PolicyVersion {
		return nil, fmt.Errorf("only exact v4 template and policy are supported")
	}
	if strings.TrimSpace(d.RecoveryKeyPub) != "" {
		return nil, fmt.Errorf("recoveryKeyPub is retired")
	}
	if d.TxCap != fixture.TxRecipientCapSats || d.PeriodAllowance != fixture.PeriodAllowanceSats ||
		d.AbsoluteFeeCap != fixture.AbsoluteFeeCeiling || d.FeerateCapSatPerV != fixture.FeerateCeilingSatPerV {
		return nil, fmt.Errorf("status policy constants do not match this release")
	}
	cfg := deployment.Config{
		ClientOrigin: d.ClientOrigin, RPID: d.RPID, Network: d.Network,
		OperationalCSVBlocks: d.OperationalCSVBlocks, SavingsCSVBlocks: d.SavingsCSVBlocks,
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	phoneRoutine, err := strictCompressedPub(d.PhoneRoutineBIP340Pub, "PhoneRoutineBIP340")
	if err != nil {
		return nil, err
	}
	externalOwner, err := strictCompressedPub(d.ExternalOwnerWalletPub, "ExternalOwnerWallet")
	if err != nil {
		return nil, err
	}
	vaultCosigner, err := strictCompressedPub(d.VaultCosignerBasePub, "VaultCosigner")
	if err != nil {
		return nil, err
	}
	arkadeCosigner, err := strictCompressedPub(d.ArkadeCosignerBasePub, "ArkadeCosigner")
	if err != nil {
		return nil, err
	}
	if err := validateArkadeReleaseIdentity(d, arkadeCosigner); err != nil {
		return nil, err
	}
	direct, err := strictHex(d.PhoneDirectP256, 33, "PhoneDirectP256")
	if err != nil {
		return nil, err
	}
	op, err := vault.NewOperationalWithPolicy(vault.OperationalKeys{
		PhoneRoutineBIP340: phoneRoutine, PhoneDirectP256: direct,
		ExternalOwnerWallet: externalOwner,
		VaultCosignerBase:   vaultCosigner, ArkadeCosignerBase: arkadeCosigner,
	}, d.Network, arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: d.OperationalCSVBlocks}, arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: d.SavingsCSVBlocks}, vault.AuthorizationPolicy{
		RecipientDustSats: fixture.DustSats, RecipientCapSats: fixture.TxRecipientCapSats,
		AbsoluteFeeCeilingSats: fixture.AbsoluteFeeCeiling, FeerateCeilingSatPerV: fixture.FeerateCeilingSatPerV,
	})
	if err != nil {
		return nil, err
	}
	if d.OperationalAddress != op.Address || !strings.EqualFold(d.OperationalScript, hex.EncodeToString(op.PkScript)) {
		return nil, fmt.Errorf("materialized Operational descriptor does not match status")
	}
	if d.TweakedVaultCosignerXOnly != hex.EncodeToString(schnorr.SerializePubKey(op.TweakedVaultCosigner)) ||
		d.TweakedArkadeCosignerXOnly != hex.EncodeToString(schnorr.SerializePubKey(op.TweakedArkadeCosigner)) {
		return nil, fmt.Errorf("materialized routine cosigner tweaks do not match status")
	}
	savings, err := vault.NewSavingsWithPolicy(
		phoneRoutine, externalOwner, d.Network,
		arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: d.OperationalCSVBlocks},
		arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: d.SavingsCSVBlocks},
		vaultCosigner, op.TweakedVaultCosigner, arkadeCosigner, op.TweakedArkadeCosigner,
	)
	if err != nil {
		return nil, err
	}
	if !d.SavingsExcludesRoutineCosigners || d.SavingsAddress != savings.Address {
		return nil, fmt.Errorf("materialized Savings descriptor does not match status")
	}
	return op, nil
}

func validateArkadeReleaseIdentity(d descriptor, arkadeCosigner *btcec.PublicKey) error {
	if d.Network != deployment.NetworkMutinynet {
		return nil
	}
	if arkadeCosigner == nil || d.ArkadeCosignerBasePub != deployment.MutinynetArkadeCosignerPubHex ||
		d.ArkadeCosignerOrigin != deployment.MutinynetArkadeCosignerOrigin ||
		d.ArkadeCosignerVersion != deployment.MutinynetArkadeCosignerVersion {
		return fmt.Errorf("Mutinynet ArkadeCosigner identity does not match this reviewed release")
	}
	return nil
}

func buildAdminPSBT(built *vault.Built, req buildRequest) (*psbt.Packet, error) {
	prevRaw, err := strictHex(req.PrevTxHex, -1, "prevTxHex")
	if err != nil {
		return nil, err
	}
	var prev wire.MsgTx
	if err := prev.Deserialize(bytes.NewReader(prevRaw)); err != nil {
		return nil, fmt.Errorf("prevTxHex: %w", err)
	}
	dest, err := strictHex(req.DestinationScript, -1, "destinationScript")
	if err != nil || len(dest) == 0 {
		return nil, fmt.Errorf("destinationScript required")
	}
	return vault.AdminSpend(
		built, &prev, wire.OutPoint{Hash: prev.TxHash(), Index: req.Vout},
		dest, req.DestinationAmount, req.Fee, wire.MaxTxInSequenceNum,
	)
}

func readPSBT(path string) (*psbt.Packet, error) {
	raw, err := readBoundedFile(path)
	if err != nil {
		return nil, err
	}
	packet, err := psbt.NewFromRawBytes(strings.NewReader(strings.TrimSpace(string(raw))), true)
	if err != nil {
		return nil, fmt.Errorf("read PSBT: %w", err)
	}
	return packet, nil
}

func strictCompressedPub(value, name string) (*btcec.PublicKey, error) {
	raw, err := strictHex(value, 33, name)
	if err != nil || (raw[0] != 0x02 && raw[0] != 0x03) {
		return nil, fmt.Errorf("%s must be canonical compressed secp256k1 hex", name)
	}
	pub, err := btcec.ParsePubKey(raw)
	if err != nil || !bytes.Equal(pub.SerializeCompressed(), raw) {
		return nil, fmt.Errorf("%s must be canonical compressed secp256k1 hex", name)
	}
	return pub, nil
}

func strictHex(value string, exactBytes int, name string) ([]byte, error) {
	if value == "" || value != strings.ToLower(value) || len(value)%2 != 0 {
		return nil, fmt.Errorf("%s must be canonical lowercase hex", name)
	}
	raw, err := hex.DecodeString(value)
	if err != nil || (exactBytes >= 0 && len(raw) != exactBytes) {
		return nil, fmt.Errorf("%s must be canonical lowercase hex", name)
	}
	return raw, nil
}

func writeExclusive(path string, raw []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	return f.Close()
}
