package application

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// A requester steers which key signs by choosing which tweaked key appears
// in the tapscript it submits (resolveArkadeScriptSigner tries the current
// key, then falls through to every deprecated key). Without a cutoff,
// deprecated keys carry indefinite signing authority. These tests pin the
// activeDeprecatedSigners cutoff behavior: unset means unbounded (today's
// behavior, unchanged for deployments that don't opt in), set means the
// deprecated keys stop being usable, for both fresh signing and
// finalization, once the cutoff has passed.
func TestActiveDeprecatedSigners(t *testing.T) {
	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	deprecated := []signer{{secretKey: key}}

	t.Run("nil cutoff is unbounded", func(t *testing.T) {
		svc := &service{deprecatedSigners: deprecated}
		require.Equal(t, deprecated, svc.activeDeprecatedSigners())
	})

	t.Run("cutoff in the future still allows deprecated keys", func(t *testing.T) {
		future := time.Now().Add(time.Hour)
		svc := &service{deprecatedSigners: deprecated, deprecatedKeysValidUntil: &future}
		require.Equal(t, deprecated, svc.activeDeprecatedSigners())
	})

	t.Run("cutoff in the past rejects deprecated keys", func(t *testing.T) {
		past := time.Now().Add(-time.Hour)
		svc := &service{deprecatedSigners: deprecated, deprecatedKeysValidUntil: &past}
		require.Empty(t, svc.activeDeprecatedSigners())
	})
}

func TestGetInfoAdvertisesOnlyActiveDeprecatedKeys(t *testing.T) {
	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	hexKey := hex.EncodeToString(key.PubKey().SerializeCompressed())
	deprecated := []signer{{secretKey: key}}
	pubkeys := []string{hexKey}

	assertAligned := func(t *testing.T, svc *service, wantActive bool) {
		t.Helper()
		info, err := svc.GetInfo(context.Background())
		require.NoError(t, err)
		if wantActive {
			require.Equal(t, deprecated, svc.activeDeprecatedSigners())
			require.Equal(t, pubkeys, info.DeprecatedSignerPublicKeys)
			return
		}
		require.Empty(t, svc.activeDeprecatedSigners())
		require.Empty(t, info.DeprecatedSignerPublicKeys)
	}

	t.Run("nil cutoff is unbounded", func(t *testing.T) {
		svc := &service{
			publicKey:            "current",
			deprecatedSigners:    deprecated,
			deprecatedPublicKeys: pubkeys,
		}
		assertAligned(t, svc, true)
		info, err := svc.GetInfo(context.Background())
		require.NoError(t, err)
		require.Equal(t, "current", info.SignerPublicKey)
	})

	t.Run("cutoff in the future still allows deprecated keys", func(t *testing.T) {
		future := time.Now().Add(time.Hour)
		svc := &service{
			deprecatedSigners:        deprecated,
			deprecatedPublicKeys:     pubkeys,
			deprecatedKeysValidUntil: &future,
		}
		assertAligned(t, svc, true)
	})

	t.Run("cutoff in the past rejects deprecated keys", func(t *testing.T) {
		past := time.Now().Add(-time.Hour)
		svc := &service{
			deprecatedSigners:        deprecated,
			deprecatedPublicKeys:     pubkeys,
			deprecatedKeysValidUntil: &past,
		}
		assertAligned(t, svc, false)
	})

	t.Run("advertised keys are a copy", func(t *testing.T) {
		svc := &service{
			deprecatedSigners:    deprecated,
			deprecatedPublicKeys: append([]string(nil), pubkeys...),
		}
		info, err := svc.GetInfo(context.Background())
		require.NoError(t, err)
		require.NotEmpty(t, info.DeprecatedSignerPublicKeys)
		info.DeprecatedSignerPublicKeys[0] = "mutated"
		require.Equal(t, hexKey, svc.deprecatedPublicKeys[0])
		again, err := svc.GetInfo(context.Background())
		require.NoError(t, err)
		require.Equal(t, []string{hexKey}, again.DeprecatedSignerPublicKeys)
	})
}
