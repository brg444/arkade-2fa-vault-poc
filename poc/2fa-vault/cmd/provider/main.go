package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/arkade-os/emulator/poc/2fa-vault/fixture"
	"github.com/arkade-os/emulator/poc/2fa-vault/internal/deployment"
	"github.com/arkade-os/emulator/poc/2fa-vault/internal/policy"
	"github.com/arkade-os/emulator/poc/2fa-vault/internal/provider"
	"github.com/arkade-os/emulator/poc/2fa-vault/internal/remotesigner"
	"github.com/btcsuite/btcd/btcec/v2"
)

func main() {
	var (
		addr           = flag.String("addr", fixture.HTTPAddr, "listen address")
		dbPath         = flag.String("db", "2fa-vault.sqlite", "sqlite path")
		webDir         = flag.String("web", "", "optional static web directory")
		hotHex         = flag.String("hot", os.Getenv("VAULT_HOT_PUB"), "optional enrolled hot pubkey hex; omit before browser enrollment")
		offlineHex     = flag.String("offline", os.Getenv("VAULT_OFFLINE_PUB"), "offline compressed pubkey hex")
		emulator       = flag.String("emulator", envOr("VAULT_EMULATOR", remotesigner.DefaultEmulatorAddr), "private emulator host:port")
		arkadeEmulator = flag.String("arkade-emulator", os.Getenv("VAULT_ARKADE_EMULATOR"), "independent regtest Arkade emulator host:port")
		unsafeLocal    = flag.Bool("unsafe-local-signer", false, "test-only: sign with a local provider private key")
		provHex        = flag.String("provider-key", os.Getenv("VAULT_PROVIDER_PRIV"), "provider private key hex (unsafe-local-signer only)")
		arkadeHex      = flag.String("arkade-key", os.Getenv("VAULT_ARKADE_PRIV"), "Arkade emulator private key hex (unsafe-local-signer only)")
		demoOn         = flag.Bool("demo", envOr("VAULT_DEMO", "") == "1", "enable gated fund/mine demo RPC")
		bitcoinRPC     = flag.String("bitcoin-rpc", os.Getenv("VAULT_BITCOIN_RPC"), "regtest Bitcoin JSON-RPC URL for Publish and demo funding")
		clientOrigin   = flag.String("client-origin", envOr("VAULT_CLIENT_ORIGIN", fixture.Origin), "exact regtest WebAuthn signing-client origin")
		rpID           = flag.String("rp-id", envOr("VAULT_RP_ID", fixture.RPID), "exact regtest WebAuthn relying-party ID")
		network        = flag.String("network", envOr("VAULT_NETWORK", deployment.NetworkRegtest), "must be regtest; Mutinynet uses cmd/authorizer")
		opCSV          = flag.Uint64("operational-csv-blocks", envUint64("VAULT_OPERATIONAL_CSV_BLOCKS"), "Operational recovery delay in blocks")
		savingsCSV     = flag.Uint64("savings-csv-blocks", envUint64("VAULT_SAVINGS_CSV_BLOCKS"), "Savings recovery delay in blocks")
	)
	flag.Parse()
	if err := requireRegtestProvider(*network); err != nil {
		log.Fatal(err)
	}
	if *opCSV == 0 {
		*opCSV = uint64(fixture.OperationalCSVBlocks)
	}
	if *savingsCSV == 0 {
		*savingsCSV = uint64(fixture.SavingsCSVBlocks)
	}
	if *opCSV > uint64(deployment.MaxCSVBlockDelay) || *savingsCSV > uint64(deployment.MaxCSVBlockDelay) {
		log.Fatalf("CSV block delays must not exceed %d", deployment.MaxCSVBlockDelay)
	}
	runtime := deployment.Config{
		ClientOrigin: *clientOrigin, RPID: *rpID, Network: *network,
		OperationalCSVBlocks: uint32(*opCSV), SavingsCSVBlocks: uint32(*savingsCSV),
	}
	if err := runtime.Validate(); err != nil {
		log.Fatalf("deployment: %v", err)
	}
	if *offlineHex == "" {
		log.Fatal("VAULT_OFFLINE_PUB / -offline is required (compressed pubkey only)")
	}
	offline, err := parseCompressedPub(*offlineHex, "offline pubkey")
	if err != nil {
		log.Fatal(err)
	}

	led, err := policy.OpenLedger(*dbPath, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer led.Close()

	svc := &provider.Service{Ledger: led, Offline: offline, Deployment: runtime}
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
		if *provHex == "" || *arkadeHex == "" {
			log.Fatal("-provider-key and -arkade-key are required with -unsafe-local-signer")
		}
		privBytes, err := hex.DecodeString(*provHex)
		if err != nil || len(privBytes) != 32 {
			log.Fatal("provider-key must be 32-byte hex")
		}
		priv, _ := btcec.PrivKeyFromBytes(privBytes)
		arkadeBytes, err := hex.DecodeString(*arkadeHex)
		if err != nil || len(arkadeBytes) != 32 {
			log.Fatal("arkade-key must be 32-byte hex")
		}
		arkadePriv, _ := btcec.PrivKeyFromBytes(arkadeBytes)
		if priv.PubKey().IsEqual(arkadePriv.PubKey()) {
			log.Fatal("provider and Arkade emulator keys must be independent")
		}
		svc.ProviderPub = priv.PubKey()
		svc.ArkadePub = arkadePriv.PubKey()
		svc.Signer = provider.LocalSigner{Priv: priv}
		svc.ArkadeSigner = provider.LocalSigner{Priv: arkadePriv}
		log.Print("UNSAFE local signer enabled; not a deployment demonstration")
	} else {
		if *arkadeEmulator == "" {
			log.Fatal("VAULT_ARKADE_EMULATOR / -arkade-emulator is required")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cli, pub, deprecated, conn, err := remotesigner.DialEmulator(ctx, *emulator)
		if err != nil {
			cancel()
			log.Fatalf("emulator at %s: %v", *emulator, err)
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
			log.Fatal("provider and Arkade emulators advertise the same key")
		}
		svc.ProviderPub = pub
		svc.DeprecatedProvider = deprecated
		svc.ArkadePub = arkadePub
		svc.DeprecatedArkade = arkadeDeprecated
		svc.Signer = &provider.RemoteSigner{Client: cli}
		svc.ArkadeSigner = &provider.RemoteSigner{Client: arkadeCli}
		log.Printf("remote provider emulator %s pubkey %x", *emulator, pub.SerializeCompressed())
		log.Printf("remote arkade emulator %s pubkey %x", *arkadeEmulator, arkadePub.SerializeCompressed())
		log.Printf("open %s", runtime.ClientOrigin)
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
	log.Printf("provider listening for client origin %s on %s", runtime.ClientOrigin, *addr)
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

func envUint64(key string) uint64 {
	raw := os.Getenv(key)
	if raw == "" {
		return 0
	}
	n, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		log.Fatalf("%s must be a uint32", key)
	}
	return n
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

func parseCompressedPub(h, name string) (*btcec.PublicKey, error) {
	raw, err := hex.DecodeString(h)
	if err != nil || len(raw) != 33 || (raw[0] != 0x02 && raw[0] != 0x03) {
		return nil, fmt.Errorf("%s must be 33-byte compressed hex", name)
	}
	pub, err := btcec.ParsePubKey(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return pub, nil
}

func requireRegtestProvider(network string) error {
	if network != deployment.NetworkRegtest {
		return fmt.Errorf("cmd/provider is the regtest RemoteSigner demo; Mutinynet must use cmd/authorizer")
	}
	return nil
}
