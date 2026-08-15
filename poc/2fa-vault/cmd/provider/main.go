package main

import (
	"context"
	"encoding/hex"
	"flag"
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
	var (
		addr        = flag.String("addr", fixture.HTTPAddr, "listen address")
		dbPath      = flag.String("db", "2fa-vault.sqlite", "sqlite path")
		webDir      = flag.String("web", "", "optional static web directory")
		hotHex      = flag.String("hot", os.Getenv("VAULT_HOT_PUB"), "optional enrolled hot pubkey hex; omit before browser enrollment")
		offlineHex  = flag.String("offline", os.Getenv("VAULT_OFFLINE_PUB"), "offline compressed pubkey hex")
		emulator    = flag.String("emulator", envOr("VAULT_EMULATOR", provider.DefaultEmulatorAddr), "private emulator host:port")
		unsafeLocal = flag.Bool("unsafe-local-signer", false, "test-only: sign with a local provider private key")
		provHex     = flag.String("provider-key", os.Getenv("VAULT_PROVIDER_PRIV"), "provider private key hex (unsafe-local-signer only)")
		demoOn      = flag.Bool("demo", envOr("VAULT_DEMO", "") == "1", "enable gated fund/mine demo RPC")
		bitcoinRPC  = flag.String("bitcoin-rpc", os.Getenv("VAULT_BITCOIN_RPC"), "Bitcoin JSON-RPC URL for Publish and demo funding")
	)
	flag.Parse()

	if *offlineHex == "" {
		log.Fatal("VAULT_OFFLINE_PUB / -offline is required (compressed pubkey only)")
	}
	offline, err := parsePub(*offlineHex)
	if err != nil {
		log.Fatal(err)
	}

	led, err := policy.OpenLedger(*dbPath, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer led.Close()

	svc := &provider.Service{Ledger: led, Offline: offline}
	if *hotHex != "" {
		hot, err := parsePub(*hotHex)
		if err != nil {
			log.Fatal(err)
		}
		svc.Hot = hot
	}

	if *demoOn && *unsafeLocal {
		log.Fatal("VAULT_DEMO=1 requires RemoteSigner; -unsafe-local-signer is incompatible")
	}

	if *unsafeLocal {
		if *provHex == "" {
			log.Fatal("-provider-key is required with -unsafe-local-signer")
		}
		privBytes, err := hex.DecodeString(*provHex)
		if err != nil || len(privBytes) != 32 {
			log.Fatal("provider-key must be 32-byte hex")
		}
		priv, _ := btcec.PrivKeyFromBytes(privBytes)
		svc.ProviderPub = priv.PubKey()
		svc.Signer = provider.LocalSigner{Priv: priv}
		log.Print("UNSAFE local signer enabled; not a deployment demonstration")
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cli, pub, deprecated, conn, err := provider.DialEmulator(ctx, *emulator)
		cancel()
		if err != nil {
			log.Fatalf("emulator at %s: %v", *emulator, err)
		}
		defer conn.Close()
		svc.ProviderPub = pub
		svc.DeprecatedProvider = deprecated
		svc.Signer = &provider.RemoteSigner{Client: cli}
		log.Printf("remote emulator signer %s pubkey %x", *emulator, pub.SerializeCompressed())
		log.Printf("open %s", fixture.Origin)
	}

	if err := svc.LoadVaults(); err != nil {
		log.Fatal(err)
	}

	var demo *provider.Demo
	if *bitcoinRPC != "" {
		rpcCtx, rpcCancel := context.WithTimeout(context.Background(), 15*time.Second)
		chain, err := provider.DialBitcoinRPC(rpcCtx, *bitcoinRPC)
		rpcCancel()
		if err != nil {
			log.Fatalf("bitcoin rpc: %v", err)
		}
		svc.Broadcaster = &provider.NodeBroadcaster{Chain: chain}
		if *demoOn {
			demo, err = provider.NewDemo(svc, chain)
			if err != nil {
				log.Fatalf("demo: %v", err)
			}
			log.Print("DEMO CONTROL ENABLED: /v1/demo/fund|mine ; Publish uses Bitcoin RPC")
		} else {
			log.Print("Publish enabled via VAULT_BITCOIN_RPC; demo fund/mine remain off")
		}
	} else if *demoOn {
		log.Fatal("VAULT_DEMO=1 requires VAULT_BITCOIN_RPC")
	}

	dir := *webDir
	if dir != "" {
		dir, _ = filepath.Abs(dir)
	}
	log.Printf("provider listening on %s", fixture.Origin)
	if svc.Operational != nil {
		log.Printf("operational %s", svc.Operational.Address)
		log.Printf("savings %s", svc.Savings.Address)
	} else {
		log.Print("not enrolled yet")
	}
	if err := provider.NewServer(*addr, provider.NewHandler(svc, dir, demo)).ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func parsePub(h string) (*btcec.PublicKey, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	return btcec.ParsePubKey(b)
}
