package provider

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

// DialEmulator connects to the private Emulator and returns its current
// signer pubkey plus any deprecated signer pubkeys GetInfo advertises.
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
	for _, h := range info.DeprecatedSignerPublicKeys {
		d, err := parseCompressedHex(h)
		if err != nil {
			_ = conn.Close()
			return nil, nil, nil, nil, fmt.Errorf("deprecated signer: %w", err)
		}
		deprecated = append(deprecated, d)
	}
	return cli, pub, deprecated, conn, nil
}

func parseCompressedHex(h string) (*btcec.PublicKey, error) {
	raw, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	return btcec.ParsePubKey(raw)
}
