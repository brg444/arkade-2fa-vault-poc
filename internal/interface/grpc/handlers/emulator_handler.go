package handlers

import (
	"context"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	emulatorv1 "github.com/arkade-os/emulator/api-spec/protobuf/gen/emulator/v1"
	"github.com/arkade-os/emulator/internal/application"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcutil/psbt"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// internalErrMsg is returned in place of an unexpected error. The detail is
// logged server-side instead of being echoed back, since callers reaching these
// endpoints are unauthenticated and the underlying errors can carry
// implementation detail. Validation errors stay descriptive so that a
// legitimate caller can fix its request.
const internalErrMsg = "internal error"

// The packet format itself permits at most MaxEntryCount script executions.
// Apply the same ceiling to request collections and transaction maps before
// iterating or performing cryptographic work so a single bounded-size protobuf
// cannot amplify into an excessive number of parses or signatures.
const maxRequestItems = arkade.MaxEntryCount

type handler struct {
	version string
	svc     application.Service
}

func New(version string, service application.Service) *handler {
	return &handler{version: version, svc: service}
}

func (h *handler) GetInfo(
	ctx context.Context, _ *emulatorv1.GetInfoRequest,
) (*emulatorv1.GetInfoResponse, error) {
	info, err := h.svc.GetInfo(ctx)
	if err != nil {
		return nil, err
	}

	return &emulatorv1.GetInfoResponse{
		SignerPubkey:            info.SignerPublicKey,
		DeprecatedSignerPubkeys: append([]string(nil), info.DeprecatedSignerPublicKeys...),
		Version:                 h.version,
	}, nil
}

func (h *handler) SubmitTx(
	ctx context.Context, req *emulatorv1.SubmitTxRequest,
) (*emulatorv1.SubmitTxResponse, error) {
	arkTx := req.GetArkTx()
	checkpoints := req.GetCheckpointTxs()

	if len(arkTx) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing ark tx")
	}

	if len(checkpoints) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing checkpoint txs")
	}
	if len(checkpoints) > maxRequestItems {
		return nil, status.Error(codes.InvalidArgument, "too many checkpoint txs")
	}

	arkPtx, err := parsePsbt(arkTx)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid ark tx")
	}
	if err := validatePacketComplexity(arkPtx); err != nil {
		return nil, status.Error(codes.InvalidArgument, "ark tx exceeds complexity limit")
	}

	checkpointPsbt := make([]*psbt.Packet, 0, len(checkpoints))
	for _, checkpoint := range checkpoints {
		checkpointPtx, err := parsePsbt(checkpoint)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid checkpoint tx")
		}
		if err := validatePacketComplexity(checkpointPtx); err != nil {
			return nil, status.Error(codes.InvalidArgument, "checkpoint tx exceeds complexity limit")
		}
		checkpointPsbt = append(checkpointPsbt, checkpointPtx)
	}

	offchainTx := application.OffchainTx{
		ArkTx:       arkPtx,
		Checkpoints: checkpointPsbt,
	}

	approvedTx, err := h.svc.SubmitTx(ctx, offchainTx)
	if err != nil {
		log.WithError(err).Error("failed to process transaction")
		return nil, status.Error(codes.Internal, internalErrMsg)
	}

	encodedArkTx, err := approvedTx.ArkTx.B64Encode()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to encode ark tx")
	}

	encodedCheckpointTxs := make([]string, 0, len(approvedTx.Checkpoints))
	for _, checkpoint := range approvedTx.Checkpoints {
		encodedCheckpointTx, err := checkpoint.B64Encode()
		if err != nil {
			return nil, status.Error(codes.Internal, "failed to encode checkpoint tx")
		}
		encodedCheckpointTxs = append(encodedCheckpointTxs, encodedCheckpointTx)
	}

	return &emulatorv1.SubmitTxResponse{
		SignedArkTx:         encodedArkTx,
		SignedCheckpointTxs: encodedCheckpointTxs,
	}, nil
}

func (h *handler) SubmitIntent(
	ctx context.Context, req *emulatorv1.SubmitIntentRequest,
) (*emulatorv1.SubmitIntentResponse, error) {
	unsignedIntent := req.GetIntent()

	if unsignedIntent == nil {
		return nil, status.Error(codes.InvalidArgument, "missing intent")
	}

	intent, err := parseIntent(unsignedIntent)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("invalid intent: %v", err))
	}
	if err := validatePacketComplexity(&intent.Proof.Packet); err != nil {
		return nil, status.Error(codes.InvalidArgument, "intent proof exceeds complexity limit")
	}

	signedIntentProof, err := h.svc.SubmitIntent(ctx, *intent)
	if err != nil {
		log.WithError(err).Error("failed to process intent")
		return nil, status.Error(codes.Internal, internalErrMsg)
	}

	encodedProof, err := signedIntentProof.B64Encode()
	if err != nil {
		log.WithError(err).Error("failed to encode intent proof")
		return nil, status.Error(codes.Internal, internalErrMsg)
	}

	return &emulatorv1.SubmitIntentResponse{
		SignedProof: encodedProof,
	}, nil
}

func (h *handler) SubmitFinalization(
	ctx context.Context, req *emulatorv1.SubmitFinalizationRequest,
) (*emulatorv1.SubmitFinalizationResponse, error) {
	signedIntent := req.GetSignedIntent()
	forfeitTxs := req.GetForfeits()
	connectorTree := req.GetConnectorTree()
	commitmentTx := req.GetCommitmentTx()

	if signedIntent == nil {
		return nil, status.Error(codes.InvalidArgument, "missing signed intent")
	}
	if len(forfeitTxs) > maxRequestItems {
		return nil, status.Error(codes.InvalidArgument, "too many forfeit txs")
	}
	if len(connectorTree) > maxRequestItems {
		return nil, status.Error(codes.InvalidArgument, "connector tree exceeds complexity limit")
	}

	intent, err := parseIntent(signedIntent)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("invalid signed intent: %v", err))
	}
	if err := validatePacketComplexity(&intent.Proof.Packet); err != nil {
		return nil, status.Error(codes.InvalidArgument, "signed intent exceeds complexity limit")
	}

	if len(commitmentTx) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing commitment tx")
	}

	commitmentPtx, err := parsePsbt(commitmentTx)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid commitment tx")
	}
	if err := validatePacketComplexity(commitmentPtx); err != nil {
		return nil, status.Error(codes.InvalidArgument, "commitment tx exceeds complexity limit")
	}

	forfeitPsbt := make([]*psbt.Packet, 0, len(forfeitTxs))
	for _, forfeit := range forfeitTxs {
		forfeitPtx, err := parsePsbt(forfeit)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid forfeit tx")
		}
		if err := validatePacketComplexity(forfeitPtx); err != nil {
			return nil, status.Error(codes.InvalidArgument, "forfeit tx exceeds complexity limit")
		}
		forfeitPsbt = append(forfeitPsbt, forfeitPtx)
	}

	batchFinalization := application.BatchFinalization{
		Intent:       *intent,
		Forfeits:     forfeitPsbt,
		CommitmentTx: commitmentPtx,
	}

	if len(forfeitPsbt) > 0 {
		if len(connectorTree) <= 0 {
			return nil, status.Error(codes.InvalidArgument, "missing connector tree")
		}

		connectorTxTree, err := parseTxTree(connectorTree)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("invalid connector tree: %v", err))
		}

		if err := verifyTreeRelatedToCommitment(commitmentPtx, connectorTxTree); err != nil {
			return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("invalid connector tree: %v", err))
		}

		batchFinalization.ConnectorTree = connectorTxTree
	}

	signedBatchFinalization, err := h.svc.SubmitFinalization(ctx, batchFinalization)
	if err != nil {
		log.WithError(err).Error("failed to process finalization")
		return nil, status.Error(codes.Internal, internalErrMsg)
	}

	encodedForfeits := make([]string, 0, len(signedBatchFinalization.Forfeits))
	for _, forfeit := range signedBatchFinalization.Forfeits {
		encodedForfeit, err := forfeit.B64Encode()
		if err != nil {
			return nil, status.Error(codes.Internal, "failed to encode forfeit")
		}
		encodedForfeits = append(encodedForfeits, encodedForfeit)
	}

	resp := &emulatorv1.SubmitFinalizationResponse{
		SignedForfeits: encodedForfeits,
	}

	if signedBatchFinalization.CommitmentTx != nil {
		encodedCommitmentTx, err := signedBatchFinalization.CommitmentTx.B64Encode()
		if err != nil {
			return nil, status.Error(codes.Internal, "failed to encode commitment tx")
		}
		resp.SignedCommitmentTx = encodedCommitmentTx
	}

	return resp, nil
}

func (h *handler) SubmitOnchainTx(
	ctx context.Context, req *emulatorv1.SubmitOnchainTxRequest,
) (*emulatorv1.SubmitOnchainTxResponse, error) {
	b64 := req.GetTx()
	if len(b64) == 0 {
		return nil, status.Error(codes.InvalidArgument, "missing tx")
	}

	ptx, err := parsePsbt(b64)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid tx")
	}
	if err := validatePacketComplexity(ptx); err != nil {
		return nil, status.Error(codes.InvalidArgument, "tx exceeds complexity limit")
	}

	signed, err := h.svc.SubmitOnchainTx(ctx, application.OnchainTx{Tx: ptx})
	if err != nil {
		log.WithError(err).Error("failed to process onchain tx")
		return nil, status.Error(codes.Internal, internalErrMsg)
	}

	encoded, err := signed.B64Encode()
	if err != nil {
		log.WithError(err).Error("failed to encode onchain tx")
		return nil, status.Error(codes.Internal, internalErrMsg)
	}

	return &emulatorv1.SubmitOnchainTxResponse{SignedTx: encoded}, nil
}

func validatePacketComplexity(ptx *psbt.Packet) error {
	if ptx == nil || ptx.UnsignedTx == nil {
		return fmt.Errorf("missing unsigned transaction")
	}
	if len(ptx.UnsignedTx.TxIn) > maxRequestItems ||
		len(ptx.UnsignedTx.TxOut) > maxRequestItems ||
		len(ptx.Inputs) > maxRequestItems || len(ptx.Outputs) > maxRequestItems {
		return fmt.Errorf("transaction map exceeds %d items", maxRequestItems)
	}
	return nil
}

func verifyTreeRelatedToCommitment(commitmentPtx *psbt.Packet, txTree *tree.TxTree) error {
	if len(txTree.Root.Inputs) != len(commitmentPtx.UnsignedTx.TxIn) {
		return fmt.Errorf("invalid number of inputs")
	}
	if len(txTree.Root.UnsignedTx.TxIn) != 1 {
		return fmt.Errorf("invalid tx tree root")
	}

	rootInput := txTree.Root.UnsignedTx.TxIn[0]
	if rootInput.PreviousOutPoint.Hash.String() != commitmentPtx.UnsignedTx.TxID() {
		return fmt.Errorf("root is not commitment tx")
	}

	if int(rootInput.PreviousOutPoint.Index) >= len(commitmentPtx.UnsignedTx.TxOut) {
		return fmt.Errorf("root input index out of range")
	}

	return nil
}

func parseTxTree(fromProto []*emulatorv1.TxTreeNode) (*tree.TxTree, error) {
	flat := make(tree.FlatTxTree, 0)
	for _, node := range fromProto {
		flat = append(flat, tree.TxTreeNode{
			Txid:     node.GetTxid(),
			Tx:       node.GetTx(),
			Children: node.GetChildren(),
		})
	}

	txTree, err := tree.NewTxTree(flat)
	if err != nil {
		return nil, fmt.Errorf("failed to create tx tree: %w", err)
	}
	if err := txTree.Validate(); err != nil {
		return nil, fmt.Errorf("invalid tx tree: %w", err)
	}

	return txTree, nil
}
