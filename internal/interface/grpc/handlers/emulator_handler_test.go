package handlers

import (
	"context"
	"fmt"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	emulatorv1 "github.com/arkade-os/emulator/api-spec/protobuf/gen/emulator/v1"
	"github.com/arkade-os/emulator/internal/application"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// leakyDetail stands in for the kind of implementation detail an internal error
// can carry: paths, key material identifiers, internal state.
const leakyDetail = "/opt/signer/keys/secret.db: deprecated key #3 rejected sighash"

// failingService returns an error carrying leakyDetail from every signing call.
type failingService struct{}

func (failingService) GetInfo(context.Context) (*application.Info, error) {
	return nil, fmt.Errorf("boom: %s", leakyDetail)
}

func (failingService) SubmitTx(
	context.Context, application.OffchainTx,
) (*application.OffchainTx, error) {
	return nil, fmt.Errorf("boom: %s", leakyDetail)
}

func (failingService) SubmitIntent(
	context.Context, application.Intent,
) (*psbt.Packet, error) {
	return nil, fmt.Errorf("boom: %s", leakyDetail)
}

func (failingService) SubmitFinalization(
	context.Context, application.BatchFinalization,
) (*application.SignedBatchFinalization, error) {
	return nil, fmt.Errorf("boom: %s", leakyDetail)
}

func (failingService) SubmitOnchainTx(
	context.Context, application.OnchainTx,
) (*psbt.Packet, error) {
	return nil, fmt.Errorf("boom: %s", leakyDetail)
}

func (failingService) Close() {}

// requireGenericInternal asserts the caller got a generic Internal error with no
// trace of the underlying detail.
func requireGenericInternal(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok, "expected a grpc status error, got %v", err)
	require.Equal(t, codes.Internal, st.Code())
	require.NotContains(t, st.Message(), leakyDetail)
	require.NotContains(t, st.Message(), "boom")
	require.Equal(t, internalErrMsg, st.Message())
}

// newIntentProto builds an intent the parser accepts, so the request reaches
// the application service.
func newIntentProto(t *testing.T) *emulatorv1.Intent {
	t.Helper()
	msg := intent.DeleteMessage{
		BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeDelete},
	}
	return &emulatorv1.Intent{
		Proof:   newProofB64(t),
		Message: encodeMsg(t, msg),
	}
}

// TestInternalErrorsAreNotLeaked proves each signing endpoint returns a generic
// message rather than the raw internal error, which is reachable by
// unauthenticated callers.
func TestInternalErrorsAreNotLeaked(t *testing.T) {
	h := New("test", failingService{})
	ctx := context.Background()
	ptx := newProofB64(t)

	t.Run("SubmitTx", func(t *testing.T) {
		_, err := h.SubmitTx(ctx, &emulatorv1.SubmitTxRequest{
			ArkTx:         ptx,
			CheckpointTxs: []string{ptx},
		})
		requireGenericInternal(t, err)
	})

	t.Run("SubmitIntent", func(t *testing.T) {
		_, err := h.SubmitIntent(ctx, &emulatorv1.SubmitIntentRequest{
			Intent: newIntentProto(t),
		})
		requireGenericInternal(t, err)
	})

	t.Run("SubmitFinalization", func(t *testing.T) {
		_, err := h.SubmitFinalization(ctx, &emulatorv1.SubmitFinalizationRequest{
			SignedIntent: newIntentProto(t),
			CommitmentTx: ptx,
		})
		requireGenericInternal(t, err)
	})

	t.Run("SubmitOnchainTx", func(t *testing.T) {
		_, err := h.SubmitOnchainTx(ctx, &emulatorv1.SubmitOnchainTxRequest{
			Tx: ptx,
		})
		requireGenericInternal(t, err)
	})
}

// TestValidationErrorsStayDescriptive pins the other half of the fix: errors a
// legitimate caller needs in order to correct its request are not genericized.
func TestValidationErrorsStayDescriptive(t *testing.T) {
	h := New("test", failingService{})
	ctx := context.Background()

	_, err := h.SubmitTx(ctx, &emulatorv1.SubmitTxRequest{})
	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.InvalidArgument, st.Code())
	require.Equal(t, "missing ark tx", st.Message())

	_, err = h.SubmitOnchainTx(ctx, &emulatorv1.SubmitOnchainTxRequest{Tx: "not-a-psbt"})
	st, ok = status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.InvalidArgument, st.Code())
	require.Equal(t, "invalid tx", st.Message())
}

func TestSigningEndpointsRejectExcessiveCollectionsBeforeParsing(t *testing.T) {
	h := New("test", failingService{})
	ctx := context.Background()
	ptx := newProofB64(t)

	_, err := h.SubmitTx(ctx, &emulatorv1.SubmitTxRequest{
		ArkTx:         ptx,
		CheckpointTxs: make([]string, maxRequestItems+1),
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.ErrorContains(t, err, "too many checkpoint txs")

	_, err = h.SubmitFinalization(ctx, &emulatorv1.SubmitFinalizationRequest{
		SignedIntent: newIntentProto(t),
		CommitmentTx: ptx,
		Forfeits:     make([]string, maxRequestItems+1),
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.ErrorContains(t, err, "too many forfeit txs")

	_, err = h.SubmitFinalization(ctx, &emulatorv1.SubmitFinalizationRequest{
		SignedIntent:  newIntentProto(t),
		CommitmentTx:  ptx,
		ConnectorTree: make([]*emulatorv1.TxTreeNode, maxRequestItems+1),
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.ErrorContains(t, err, "connector tree exceeds complexity limit")
}

func TestSigningEndpointRejectsExcessivePSBTInputsBeforeService(t *testing.T) {
	tx := wire.NewMsgTx(2)
	for i := range maxRequestItems + 1 {
		tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: uint32(i)}})
	}
	tx.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{0x51}})
	packet, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	encoded, err := packet.B64Encode()
	require.NoError(t, err)

	h := New("test", failingService{})
	_, err = h.SubmitOnchainTx(context.Background(), &emulatorv1.SubmitOnchainTxRequest{Tx: encoded})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.ErrorContains(t, err, "complexity limit")
}
