// Command demo is the labeled REGTEST POC harness. It may generate fixture
// PhoneRoutineBIP340, ExternalOwnerWallet, and RecoveryKey files under -data.
// These are ordinary test signers, not hardware or isolated ceremonies.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/arkade-os/emulator/poc/2fa-vault/fixture"
	"github.com/arkade-os/emulator/poc/2fa-vault/internal/policy"
	"github.com/arkade-os/emulator/poc/2fa-vault/internal/provider"
	"github.com/arkade-os/emulator/poc/2fa-vault/internal/remotesigner"
	"github.com/btcsuite/btcd/btcec/v2"
)

func main() {
	log.Print("POC harness: fixture PhoneRoutineBIP340, ExternalOwnerWallet, and RecoveryKey files under -data; no hardware claim.")
	var (
		addr           = flag.String("addr", fixture.HTTPAddr, "listen address")
		data           = flag.String("data", "poc-2fa-data", "data directory")
		webDir         = flag.String("web", "", "static web directory")
		emulator       = flag.String("emulator", envOr("VAULT_EMULATOR", remotesigner.DefaultEmulatorAddr), "private emulator host:port")
		arkadeEmulator = flag.String("arkade-emulator", os.Getenv("VAULT_ARKADE_EMULATOR"), "independent regtest Arkade emulator host:port")
		unsafeLocal    = flag.Bool("unsafe-local-signer", false, "test-only local routine cosigner keys")
	)
	flag.Parse()
	if err := os.MkdirAll(*data, 0o700); err != nil {
		log.Fatal(err)
	}

	phoneRoutine, externalOwner, recoveryKey, err := loadOrCreateUserKeys(*data)
	if err != nil {
		log.Fatal(err)
	}

	led, err := policy.OpenLedger(filepath.Join(*data, "vault.sqlite"), nil)
	if err != nil {
		log.Fatal(err)
	}
	defer led.Close()

	svc := &provider.Service{
		Ledger:              led,
		PhoneRoutineBIP340:  phoneRoutine.PubKey(),
		ExternalOwnerWallet: externalOwner.PubKey(),
	}

	if *unsafeLocal {
		vaultCosigner, err := loadOrCreateKey(filepath.Join(*data, "vault-cosigner.hex"))
		if err != nil {
			log.Fatal(err)
		}
		svc.VaultCosignerPub = vaultCosigner.PubKey()
		arkadePriv, err := loadOrCreateKey(filepath.Join(*data, "arkade-emulator.hex"))
		if err != nil {
			log.Fatal(err)
		}
		if vaultCosigner.PubKey().IsEqual(arkadePriv.PubKey()) {
			log.Fatal("VaultCosigner and ArkadeCosigner keys must be independent")
		}
		svc.ArkadeCosignerPub = arkadePriv.PubKey()
		svc.VaultSigner = provider.LocalSigner{Priv: vaultCosigner}
		svc.ArkadeCosignerSigner = provider.LocalSigner{Priv: arkadePriv}
		log.Print("UNSAFE local signer enabled; not a deployment demonstration")
	} else {
		if *arkadeEmulator == "" {
			log.Fatal("VAULT_ARKADE_EMULATOR / -arkade-emulator is required")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cli, pub, deprecated, conn, err := remotesigner.DialEmulator(ctx, *emulator)
		if err != nil {
			cancel()
			log.Fatalf("emulator at %s: %v (start the private emulator or pass -unsafe-local-signer for tests)", *emulator, err)
		}
		arkadeCli, arkadePub, arkadeDeprecated, arkadeConn, err := remotesigner.DialEmulator(ctx, *arkadeEmulator)
		cancel()
		if err != nil {
			_ = conn.Close()
			log.Fatalf("arkade emulator at %s: %v", *arkadeEmulator, err)
		}
		defer conn.Close()
		defer arkadeConn.Close()
		if pub.IsEqual(arkadePub) {
			log.Fatal("VaultCosigner and ArkadeCosigner emulators advertise the same key")
		}
		svc.VaultCosignerPub = pub
		svc.DeprecatedVaultCosigners = deprecated
		svc.ArkadeCosignerPub = arkadePub
		svc.DeprecatedArkadeCosigners = arkadeDeprecated
		svc.VaultSigner = &provider.RemoteSigner{Client: cli}
		svc.ArkadeCosignerSigner = &provider.RemoteSigner{Client: arkadeCli}
		fmt.Printf("  emulator    %s\n", *emulator)
		fmt.Printf("  arkade emu  %s\n", *arkadeEmulator)
		fmt.Printf("  VaultCosigner %x\n", pub.SerializeCompressed())
	}

	if err := svc.LoadVaults(); err != nil {
		log.Fatal(err)
	}

	web := *webDir
	if web == "" {
		candidates := []string{
			"poc/2fa-vault/web",
			filepath.Join(filepath.Dir(mustAbs(os.Args[0])), "..", "..", "web"),
		}
		for _, c := range candidates {
			if _, err := os.Stat(filepath.Join(c, "index.html")); err == nil {
				web = c
				break
			}
		}
	}

	fmt.Printf("Arkade 2FA Vault demo\n")
	fmt.Printf("  listen      %s\n", fixture.Origin)
	fmt.Printf("  PhoneRoutineBIP340  %x\n", phoneRoutine.PubKey().SerializeCompressed())
	fmt.Printf("  ExternalOwnerWallet %x\n", externalOwner.PubKey().SerializeCompressed())
	fmt.Printf("  RecoveryKey         %x\n", recoveryKey.PubKey().SerializeCompressed())
	fmt.Printf("  routine key file     %s/phone-routine.hex (harness only)\n", *data)
	if svc.Operational != nil {
		fmt.Printf("  operational %s\n", svc.Operational.Address)
		fmt.Printf("  savings     %s\n", svc.Savings.Address)
	} else {
		fmt.Printf("Register a passkey in the UI, then fund the Operational address.\n")
	}
	fmt.Printf("Do not publish emulator port 7073 to the host.\n")

	log.Fatal(provider.NewServer(*addr, provider.Handler(svc, web)).ListenAndServe())
}

func loadOrCreateUserKeys(dir string) (phoneRoutine, externalOwner, recoveryKey *btcec.PrivateKey, err error) {
	if phoneRoutine, err = loadOrCreateKey(filepath.Join(dir, "phone-routine.hex")); err != nil {
		return
	}
	if externalOwner, err = loadOrCreateKey(filepath.Join(dir, "external-owner.hex")); err != nil {
		return
	}
	recoveryKey, err = loadOrCreateKey(filepath.Join(dir, "recovery-key.hex"))
	return
}

func loadOrCreateKey(path string) (*btcec.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		raw, err := hex.DecodeString(string(bytesTrim(b)))
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("%s: bad key", path)
		}
		k, _ := btcec.PrivKeyFromBytes(raw)
		return k, nil
	}
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(seed[:])+"\n"), 0o600); err != nil {
		return nil, err
	}
	k, _ := btcec.PrivKeyFromBytes(seed[:])
	return k, nil
}

func bytesTrim(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func mustAbs(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return a
}
