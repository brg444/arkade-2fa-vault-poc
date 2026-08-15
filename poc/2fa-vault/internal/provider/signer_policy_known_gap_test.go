package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/arkade-os/emulator/poc/2fa-vault/fixture"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
)

// TestKnownTrustBoundaryRawSignerDoesNotEnforceProviderSpendingPolicy is an
// auditor-facing, intentionally green proof of the POC's current boundary.
//
// The browser-generated WebAuthn assertion, DirectP256 OP_SIGHASH witness,
// and hot signature are all valid for each transaction below.
// Service.Authorize rejects the transaction under its configured
// recipient/period policy before calling its Signer. Feeding that exact
// client-final PSBT directly to LocalSigner nevertheless releases the
// provider signature, because the committed Arkade program verifies only
// the DirectP256 sighash signature; it does not execute budget rules.
//
// LocalSigner exercises the same script-and-sign path exposed by the private
// SubmitOnchainTx endpoint. This test should be replaced by a fail-closed test
// once policy state and transaction semantics are inside the key-constrained
// signer boundary.
func TestKnownTrustBoundaryRawSignerDoesNotEnforceProviderSpendingPolicy(t *testing.T) {
	t.Run("recipient cap", func(t *testing.T) {
		e := newBoundaryEnv(t)
		draft := e.canonicalDraft(
			t, 90_000, fixture.TxRecipientCapSats+1, 500,
		)
		req, _ := e.requestFor(t, draft, e.passkeyPriv)

		if _, _, err := e.service.Authorize(context.Background(), req); err == nil {
			t.Fatal("Service.Authorize accepted a recipient above its transaction cap")
		} else if !strings.Contains(err.Error(), "recipient exceeds transaction cap") {
			t.Fatalf("Service.Authorize returned the wrong policy error: %v", err)
		}
		if got := e.countingSigner.callCount(); got != 0 {
			t.Fatalf("rejected over-cap request reached Service.Signer %d times", got)
		}

		assertRawSignerReleasesProviderSignature(t, e, req)
	})

	t.Run("period allowance", func(t *testing.T) {
		e := newBoundaryEnv(t)

		// Consume exactly the configured period allowance through the public
		// Service path. Each request has a distinct transaction/challenge.
		for i := 0; i < 2; i++ {
			draft := e.canonicalDraft(t, 90_000, fixture.TxRecipientCapSats-500, 500)
			req, _ := e.requestFor(t, draft, e.passkeyPriv)
			if _, replay, err := e.service.Authorize(context.Background(), req); err != nil {
				t.Fatalf("consume period allowance request %d: %v", i+1, err)
			} else if replay {
				t.Fatalf("consume period allowance request %d was unexpectedly a replay", i+1)
			}
		}

		draft := e.canonicalDraft(t, 90_000, 1_000, 500)
		req, _ := e.requestFor(t, draft, e.passkeyPriv)
		if _, _, err := e.service.Authorize(context.Background(), req); err == nil {
			t.Fatal("Service.Authorize accepted a transaction above the period allowance")
		} else if !strings.Contains(err.Error(), "period allowance exceeded") {
			t.Fatalf("Service.Authorize returned the wrong allowance error: %v", err)
		}
		if got := e.countingSigner.callCount(); got != 2 {
			t.Fatalf("period-policy rejection reached Service.Signer: calls=%d, want 2", got)
		}

		assertRawSignerReleasesProviderSignature(t, e, req)
	})
}

func assertRawSignerReleasesProviderSignature(
	t *testing.T, e *boundaryEnv, req AuthorizeRequest,
) {
	t.Helper()
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(req.PSBT), true)
	if err != nil {
		t.Fatalf("decode exact client-final PSBT: %v", err)
	}
	wantProvider := schnorr.SerializePubKey(e.service.Operational.TweakedProvider)
	before := len(ptx.Inputs[0].TaprootScriptSpendSig)
	signed, err := (LocalSigner{Priv: e.providerPriv}).Sign(context.Background(), ptx)
	if err != nil {
		t.Fatalf("known-boundary proof changed: raw LocalSigner rejected policy-violating transaction: %v", err)
	}
	if len(signed.Inputs[0].TaprootScriptSpendSig) != before+1 {
		t.Fatalf("raw LocalSigner signature delta: got %d signatures, want %d", len(signed.Inputs[0].TaprootScriptSpendSig), before+1)
	}
	_ = boundaryProviderSig(t, signed, wantProvider)
}
