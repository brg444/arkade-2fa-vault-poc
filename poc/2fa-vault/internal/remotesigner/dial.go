// Package remotesigner contains the regtest-only Emulator transport. The
// Mutinynet authorizer must not import this package or its gRPC dependencies.
package remotesigner

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/arkade-os/emulator/pkg/client"
	"github.com/btcsuite/btcd/btcec/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const DefaultEmulatorAddr = "127.0.0.1:7073"

// DialEmulator connects to the private regtest Emulator and returns its
// current signer pubkey plus any deprecated signer pubkeys GetInfo advertises.
func DialEmulator(ctx context.Context, addr string) (client.TransportClient, *btcec.PublicKey, []*btcec.PublicKey, *grpc.ClientConn, error) {
	if addr == "" {
		addr = DefaultEmulatorAddr
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	cli := client.NewGRPCClient(conn)
	info, err := cli.GetInfo(ctx)
	if err != nil {
		_ = conn.Close()
		return nil, nil, nil, nil, fmt.Errorf("emulator GetInfo: %w", err)
	}
	pub, err := parseCompressedHex(info.SignerPublicKey)
	if err != nil {
		_ = conn.Close()
		return nil, nil, nil, nil, err
	}
	var deprecated []*btcec.PublicKey
	for _, encoded := range info.DeprecatedSignerPublicKeys {
		key, err := parseCompressedHex(encoded)
		if err != nil {
			_ = conn.Close()
			return nil, nil, nil, nil, fmt.Errorf("deprecated signer: %w", err)
		}
		deprecated = append(deprecated, key)
	}
	return cli, pub, deprecated, conn, nil
}

func parseCompressedHex(encoded string) (*btcec.PublicKey, error) {
	raw, err := hex.DecodeString(encoded)
	if err != nil || len(raw) != 33 || (raw[0] != 0x02 && raw[0] != 0x03) {
		return nil, fmt.Errorf("emulator signer must be a compressed secp256k1 public key")
	}
	return btcec.ParsePubKey(raw)
}
