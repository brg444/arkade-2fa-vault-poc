package main

import (
	"bytes"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arkade-os/emulator/poc/2fa-vault/fixture"
	"github.com/arkade-os/emulator/poc/2fa-vault/internal/deployment"
	"github.com/arkade-os/emulator/poc/2fa-vault/internal/vault"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

type adminFixture struct {
	descriptor descriptor
	vault      *vault.Built
	phone      *btcec.PrivateKey
	owner      *btcec.PrivateKey
	vaultKey   *btcec.PrivateKey
	arkade     *btcec.PrivateKey
	prev       *wire.MsgTx
	req        buildRequest
}

func TestBuildAndFinalizeAdminHandoffRequiresExactExternalOwnerAndRecovery(t *testing.T) {
	f := newAdminFixture(t)
	packet, err := buildAdminPSBT(f.vault, f.req)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet.Inputs[0].TaprootLeafScript) != 1 ||
		!bytes.Equal(packet.Inputs[0].TaprootLeafScript[0].Script, f.vault.Leaves.Admin.Script) {
		t.Fatal("handoff PSBT does not expose the exact v4 admin leaf")
	}
	if _, err := vault.RequireVerifiedPrevout(packet); err != nil {
		t.Fatalf("handoff PSBT omitted verified previous transaction: %v", err)
	}

	addAdminSig(t, packet, f.vault, f.owner)
	if err := vault.FinalizeAdmin(packet, f.vault); err == nil {
		t.Fatal("one-of-two admin signature finalized")
	}
	addAdminSig(t, packet, f.vault, f.phone)
	if err := vault.FinalizeAdmin(packet, f.vault); err != nil {
		t.Fatalf("exact phone+hardware signatures: %v", err)
	}
	if err := vault.ExecuteFinalizedAdmin(packet, f.vault); err != nil {
		t.Fatalf("final admin witness does not execute: %v", err)
	}
	if _, err := vault.ExtractFinalizedTx(packet); err != nil {
		t.Fatal(err)
	}
}

func TestAdminHandoffPinsMutinynetArkadeCosignerReleaseIdentity(t *testing.T) {
	raw, err := hex.DecodeString(deployment.MutinynetArkadeCosignerPubHex)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := btcec.ParsePubKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	valid := descriptor{
		Network:               deployment.NetworkMutinynet,
		ArkadeCosignerBasePub: deployment.MutinynetArkadeCosignerPubHex,
		ArkadeCosignerOrigin:  deployment.MutinynetArkadeCosignerOrigin,
		ArkadeCosignerVersion: deployment.MutinynetArkadeCosignerVersion,
	}
	if err := validateArkadeReleaseIdentity(valid, pub); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*descriptor){
		func(d *descriptor) { d.ArkadeCosignerBasePub = fixture.RecoveryKeyPubHex },
		func(d *descriptor) { d.ArkadeCosignerOrigin = "https://attacker.example" },
		func(d *descriptor) { d.ArkadeCosignerVersion += "-other" },
	} {
		candidate := valid
		mutate(&candidate)
		if err := validateArkadeReleaseIdentity(candidate, pub); err == nil {
			t.Fatal("mutated Mutinynet ArkadeCosigner release identity accepted")
		}
	}
}

func TestAdminHandoffRejectsRoutineRoleSubstitutionAndPrevoutMutation(t *testing.T) {
	for _, signer := range []struct {
		name string
		key  func(*adminFixture) *btcec.PrivateKey
	}{
		{"PhoneRoutineBIP340", func(f *adminFixture) *btcec.PrivateKey { return f.phone }},
		{"VaultCosigner", func(f *adminFixture) *btcec.PrivateKey { return f.vaultKey }},
		{"ArkadeCosigner", func(f *adminFixture) *btcec.PrivateKey { return f.arkade }},
	} {
		t.Run(signer.name, func(t *testing.T) {
			f := newAdminFixture(t)
			packet, err := buildAdminPSBT(f.vault, f.req)
			if err != nil {
				t.Fatal(err)
			}
			key := signer.key(&f)
			addSigForPub(t, packet, f.vault.Leaves.Admin, key, key.PubKey())
			addAdminSig(t, packet, f.vault, f.phone)
			if err := vault.FinalizeAdmin(packet, f.vault); err == nil {
				t.Fatalf("%s substituted for ExternalOwnerWallet", signer.name)
			}
		})
	}

	f := newAdminFixture(t)
	packet, err := buildAdminPSBT(f.vault, f.req)
	if err != nil {
		t.Fatal(err)
	}
	packet.Inputs[0].WitnessUtxo.Value--
	addAdminSig(t, packet, f.vault, f.owner)
	addAdminSig(t, packet, f.vault, f.phone)
	if err := vault.FinalizeAdmin(packet, f.vault); err == nil || !strings.Contains(err.Error(), "witness utxo does not match prevout") {
		t.Fatalf("mutated prevout accepted: %v", err)
	}
}

func TestAdminHandoffCLIUsesFilesOnlyAndFailsClosedOnDescriptorVersion(t *testing.T) {
	f := newAdminFixture(t)
	dir := t.TempDir()
	descriptorPath := writeJSON(t, dir, "status.json", f.descriptor)
	requestPath := writeJSON(t, dir, "request.json", f.req)
	unsignedPath := filepath.Join(dir, "unsigned.psbt")
	if err := run("build", descriptorPath, requestPath, "", unsignedPath, ""); err != nil {
		t.Fatal(err)
	}
	packet, err := readPSBT(unsignedPath)
	if err != nil {
		t.Fatal(err)
	}
	addAdminSig(t, packet, f.vault, f.owner)
	addAdminSig(t, packet, f.vault, f.phone)
	signed, err := packet.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	signedPath := filepath.Join(dir, "signed.psbt")
	if err := os.WriteFile(signedPath, []byte(signed+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	finalPath := filepath.Join(dir, "final.psbt")
	txPath := filepath.Join(dir, "final.tx")
	if err := run("finalize", descriptorPath, "", signedPath, finalPath, txPath); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(txPath); err != nil || len(strings.TrimSpace(string(raw))) == 0 {
		t.Fatalf("final transaction missing: %v", err)
	}

	v2 := f.descriptor
	v2.TemplateVersion = "phone-direct-p256-routine-3of3-admin-2of2-v2"
	v2Path := writeJSON(t, dir, "v2-status.json", v2)
	if err := run("build", v2Path, requestPath, "", filepath.Join(dir, "v2.psbt"), ""); err == nil {
		t.Fatal("v2 descriptor was silently reinterpreted as v3")
	}

	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"ListenAndServe", "http.Handle", "PrivKeyFromBytes", "SignLeaf("} {
		if bytes.Contains(source, []byte(forbidden)) {
			t.Fatalf("file-only handoff contains forbidden signer/server primitive %q", forbidden)
		}
	}
}

func newAdminFixture(t *testing.T) adminFixture {
	t.Helper()
	key := func(n byte) *btcec.PrivateKey {
		raw := make([]byte, 32)
		raw[31] = n
		priv, _ := btcec.PrivKeyFromBytes(raw)
		return priv
	}
	f := adminFixture{
		phone: key(7), owner: key(8), vaultKey: key(10), arkade: key(11),
	}
	direct := elliptic.MarshalCompressed(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy)
	op, err := vault.NewOperationalWithPolicy(vault.OperationalKeys{
		PhoneRoutineBIP340: f.phone.PubKey(), PhoneDirectP256: direct,
		ExternalOwnerWallet: f.owner.PubKey(),
		VaultCosignerBase:   f.vaultKey.PubKey(), ArkadeCosignerBase: f.arkade.PubKey(),
	}, "regtest", fixture.OperationalCSV(), fixture.SavingsCSV(), vault.AuthorizationPolicy{
		RecipientDustSats: fixture.DustSats, RecipientCapSats: fixture.TxRecipientCapSats,
		AbsoluteFeeCeilingSats: fixture.AbsoluteFeeCeiling, FeerateCeilingSatPerV: fixture.FeerateCeilingSatPerV,
	})
	if err != nil {
		t.Fatal(err)
	}
	savings, err := vault.NewSavingsWithPolicy(
		f.phone.PubKey(), f.owner.PubKey(), "regtest", fixture.OperationalCSV(), fixture.SavingsCSV(),
		f.vaultKey.PubKey(), op.TweakedVaultCosigner, f.arkade.PubKey(), op.TweakedArkadeCosigner,
	)
	if err != nil {
		t.Fatal(err)
	}
	f.vault = op
	f.descriptor = descriptor{
		Enrolled: true, Network: "regtest", ClientOrigin: fixture.Origin, RPID: fixture.RPID,
		VaultID: fixture.VaultID, TemplateVersion: fixture.TemplateVersion, PolicyVersion: fixture.PolicyVersion,
		OperationalCSVBlocks: fixture.OperationalCSVBlocks, SavingsCSVBlocks: fixture.SavingsCSVBlocks,
		ExternalOwnerWalletPub: hex.EncodeToString(f.owner.PubKey().SerializeCompressed()),
		VaultCosignerBasePub:   hex.EncodeToString(f.vaultKey.PubKey().SerializeCompressed()),
		ArkadeCosignerBasePub:  hex.EncodeToString(f.arkade.PubKey().SerializeCompressed()),
		OperationalAddress:     op.Address, OperationalScript: hex.EncodeToString(op.PkScript),
		SavingsAddress: savings.Address, SavingsExcludesRoutineCosigners: true,
		PeriodAllowance: fixture.PeriodAllowanceSats, TxCap: fixture.TxRecipientCapSats,
		AbsoluteFeeCap: fixture.AbsoluteFeeCeiling, FeerateCapSatPerV: fixture.FeerateCeilingSatPerV,
		PhoneRoutineBIP340Pub:      hex.EncodeToString(f.phone.PubKey().SerializeCompressed()),
		PhoneDirectP256:            hex.EncodeToString(direct),
		TweakedVaultCosignerXOnly:  hex.EncodeToString(schnorr.SerializePubKey(op.TweakedVaultCosigner)),
		TweakedArkadeCosignerXOnly: hex.EncodeToString(schnorr.SerializePubKey(op.TweakedArkadeCosigner)),
	}
	f.prev = wire.NewMsgTx(2)
	f.prev.AddTxIn(&wire.TxIn{})
	f.prev.AddTxOut(&wire.TxOut{Value: 100_000, PkScript: op.PkScript})
	var prev bytes.Buffer
	if err := f.prev.Serialize(&prev); err != nil {
		t.Fatal(err)
	}
	f.req = buildRequest{
		PrevTxHex: hex.EncodeToString(prev.Bytes()), Vout: 0,
		DestinationScript: "0014" + strings.Repeat("22", 20),
		DestinationAmount: 99_000, Fee: 1_000,
	}
	return f
}

func addAdminSig(t *testing.T, packet *psbt.Packet, built *vault.Built, priv *btcec.PrivateKey) {
	t.Helper()
	addSigForPub(t, packet, built.Leaves.Admin, priv, priv.PubKey())
}

func addSigForPub(t *testing.T, packet *psbt.Packet, leaf *vault.Leaf, priv *btcec.PrivateKey, pub *btcec.PublicKey) {
	t.Helper()
	sig, err := vault.SignLeaf(packet.UnsignedTx, packet.Inputs[0].WitnessUtxo, leaf.Script, priv)
	if err != nil {
		t.Fatal(err)
	}
	vault.AddPartialSig(packet, pub, leaf.Hash, sig)
}

func writeJSON(t *testing.T, dir, name string, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
