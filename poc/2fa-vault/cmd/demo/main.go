// Command demo is the labeled POC harness. It may generate fixture
// hot.hex / offline.hex under -data. The offline key is just another
// signer in this minimal POC, not an isolated offline ceremony.
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
	"github.com/btcsuite/btcd/btcec/v2"
)

func main() {
	log.Print("POC harness: fixture hot.hex / offline.hex under -data. Offline is another signer, not an isolated ceremony.")
	var (
		addr        = flag.String("addr", fixture.HTTPAddr, "listen address")
		data        = flag.String("data", "poc-2fa-data", "data directory")
		webDir      = flag.String("web", "", "static web directory")
		emulator    = flag.String("emulator", envOr("VAULT_EMULATOR", provider.DefaultEmulatorAddr), "private emulator host:port")
		unsafeLocal = flag.Bool("unsafe-local-signer", false, "test-only local provider key")
	)
	flag.Parse()
	if err := os.MkdirAll(*data, 0o700); err != nil {
		log.Fatal(err)
	}

	hot, offline, err := loadOrCreateUserKeys(*data)
	if err != nil {
		log.Fatal(err)
	}

	led, err := policy.OpenLedger(filepath.Join(*data, "vault.sqlite"), nil)
	if err != nil {
		log.Fatal(err)
	}
	defer led.Close()

	svc := &provider.Service{
		Ledger:  led,
		Hot:     hot.PubKey(),
		Offline: offline.PubKey(),
	}

	if *unsafeLocal {
		prov, err := loadOrCreateKey(filepath.Join(*data, "provider.hex"))
		if err != nil {
			log.Fatal(err)
		}
		svc.ProviderPub = prov.PubKey()
		svc.Signer = provider.LocalSigner{Priv: prov}
		log.Print("UNSAFE local signer enabled; not a deployment demonstration")
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cli, pub, deprecated, conn, err := provider.DialEmulator(ctx, *emulator)
		cancel()
		if err != nil {
			log.Fatalf("emulator at %s: %v (start the private emulator or pass -unsafe-local-signer for tests)", *emulator, err)
		}
		defer conn.Close()
		svc.ProviderPub = pub
		svc.DeprecatedProvider = deprecated
		svc.Signer = &provider.RemoteSigner{Client: cli}
		fmt.Printf("  emulator    %s\n", *emulator)
		fmt.Printf("  provider    %x\n", pub.SerializeCompressed())
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
	fmt.Printf("  hot pub     %x\n", hot.PubKey().SerializeCompressed())
	fmt.Printf("  offline pub %x\n", offline.PubKey().SerializeCompressed())
	fmt.Printf("  hot priv    %s/hot.hex (harness only)\n", *data)
	if svc.Operational != nil {
		fmt.Printf("  operational %s\n", svc.Operational.Address)
		fmt.Printf("  savings     %s\n", svc.Savings.Address)
	} else {
		fmt.Printf("Register a passkey in the UI, then fund the Operational address.\n")
	}
	fmt.Printf("Do not publish emulator port 7073 to the host.\n")

	log.Fatal(provider.NewServer(*addr, provider.Handler(svc, web)).ListenAndServe())
}

func loadOrCreateUserKeys(dir string) (hot, offline *btcec.PrivateKey, err error) {
	if hot, err = loadOrCreateKey(filepath.Join(dir, "hot.hex")); err != nil {
		return
	}
	offline, err = loadOrCreateKey(filepath.Join(dir, "offline.hex"))
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
