package application

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	arkintent "github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	log "github.com/sirupsen/logrus"
)

// SubmitIntent aims to execute arkade scripts on unsigned intent proof
// it must be used before registration of the intent
func (s *service) SubmitIntent(ctx context.Context, intent Intent) (*psbt.Packet, error) {
	if err := validateMessage(intent.Message); err != nil {
		return nil, fmt.Errorf("invalid message: %w", err)
	}

	ptx := &intent.Proof.Packet
	deprecatedSigners := s.activeDeprecatedSigners()

	prevOutFetcher, err := prevOutFetcherForIntent(ptx)
	if err != nil {
		return nil, fmt.Errorf("failed to create prevout fetcher: %w", err)
	}

	// The BIP322-shaped message input commits the encoded intent in its
	// previous-outpoint hash. Validating only the separately supplied message's
	// time window would allow the service to sign a proof that commits a
	// different message. Verify that structural binding before executing or
	// adding any signer signature. Full ark-lib intent verification is not used
	// here because the emulator's tweaked signature is intentionally absent at
	// this pre-signing stage.
	if err := validateIntentMessageCommitment(ptx, intent.Message); err != nil {
		return nil, fmt.Errorf("intent proof does not commit the supplied message: %w", err)
	}

	// Parse EmulatorPacket from the transaction's OP_RETURN output
	packet, err := arkade.FindEmulatorPacket(ptx.UnsignedTx)
	if err != nil {
		return nil, fmt.Errorf("failed to parse emulator packet: %w", err)
	}

	if len(packet) == 0 {
		return nil, fmt.Errorf("no emulator packet found in transaction")
	}

	budget := arkade.NewComputeBudgetWithLimits(arkade.AggregateComputeLimits(s.computeLimits))

	var nSigned = 0
	for _, entry := range packet {
		inputIndex := int(entry.Vin)

		if inputIndex == 0 {
			// in intent proof, input index 0 is the message input
			// the signature script equals to the input 1 script
			// so we can skip it and handle it later if input index 1 is an arkade script
			continue
		}

		matchedSigner, script, err := resolveArkadeScriptSigner(s.signer, deprecatedSigners, ptx, entry)
		if err != nil {
			// there may be input/entry pairs attributed to a different signer
			if errors.Is(err, arkade.ErrTweakedArkadePubKeyNotFound) && len(ptx.Inputs) > 1 {
				continue
			}
			return nil, fmt.Errorf("failed to read arkade script: %w vin=%d", err, inputIndex)
		}

		if err := script.Execute(
			ptx.UnsignedTx,
			prevOutFetcher,
			inputIndex,
			arkade.WithExactComputeLimits(s.computeLimits),
			arkade.WithComputeBudget(budget),
		); err != nil {
			log.WithError(err).WithField("input_index", inputIndex).Error("arkade script execution failed")
			return nil, fmt.Errorf("failed to execute arkade script at input %d: %w", inputIndex, err)
		}

		if err := matchedSigner.signInput(ptx, inputIndex, script.Hash(), prevOutFetcher); err != nil {
			return nil, fmt.Errorf("failed to sign input %d: %w", inputIndex, err)
		}

		// if input index 1 is valid and signed, we can also sign the intent message input (index 0)
		if inputIndex == 1 {
			// the message input is signed with input 1's script hash, so it must
			// really carry input 1's script: the vm never executes input 0 on its
			// own, nothing else would bind the signature to the executed script
			if !bytes.Equal(
				ptx.Inputs[0].WitnessUtxo.PkScript, ptx.Inputs[1].WitnessUtxo.PkScript,
			) {
				return nil, fmt.Errorf("message input script does not match input 1 script")
			}

			if err := matchedSigner.signInput(ptx, 0, script.Hash(), prevOutFetcher); err != nil {
				return nil, fmt.Errorf("failed to sign fake message input: %w", err)
			}
		}

		nSigned++
	}

	if nSigned == 0 {
		return nil, fmt.Errorf("failed to find any valid input/entry pairs")
	}

	return ptx, nil
}

var intentMessageTag = []byte("ark-intent-proof-message")

func validateIntentMessageCommitment(ptx *psbt.Packet, message IntentMessage) error {
	if ptx == nil || ptx.UnsignedTx == nil || len(ptx.UnsignedTx.TxIn) < 2 ||
		len(ptx.Inputs) < 2 || ptx.Inputs[1].WitnessUtxo == nil {
		return fmt.Errorf("malformed intent proof")
	}

	encoded, err := message.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode message: %w", err)
	}
	messageHash := chainhash.TaggedHash(intentMessageTag, []byte(encoded))
	toSpend := wire.NewMsgTx(0)
	toSpend.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  chainhash.Hash{},
			Index: wire.MaxPrevOutIndex,
		},
		Sequence:        0,
		SignatureScript: append([]byte{txscript.OP_0, txscript.OP_DATA_32}, messageHash[:]...),
	})
	toSpend.AddTxOut(&wire.TxOut{
		Value:    0,
		PkScript: ptx.Inputs[1].WitnessUtxo.PkScript,
	})

	messageOutpoint := ptx.UnsignedTx.TxIn[0].PreviousOutPoint
	if messageOutpoint.Hash != toSpend.TxHash() {
		return arkintent.ErrInvalidTxWrongTxHash
	}
	if messageOutpoint.Index != 0 {
		return arkintent.ErrInvalidTxWrongOutputIndex
	}

	return nil
}

// validateMessage checks the proof's validity window. Register and estimate-fee
// carry ValidAt+ExpireAt; the rest only ExpireAt, read here via a type switch.
func validateMessage(message IntentMessage) error {
	var validAt, expireAt int64
	switch m := message.(type) {
	case *arkintent.RegisterMessage:
		validAt, expireAt = m.ValidAt, m.ExpireAt
	case *arkintent.EstimateIntentFeeMessage:
		validAt, expireAt = m.ValidAt, m.ExpireAt
	case *arkintent.DeleteMessage:
		expireAt = m.ExpireAt
	case *arkintent.GetPendingTxMessage:
		expireAt = m.ExpireAt
	case *arkintent.GetIntentMessage:
		expireAt = m.ExpireAt
	case *arkintent.GetDataMessage:
		expireAt = m.ExpireAt
	default:
		return fmt.Errorf("unsupported intent message type")
	}

	now := time.Now()
	if expireAt > 0 && time.Unix(expireAt, 0).Before(now) {
		return fmt.Errorf("intent message expired")
	}
	if validAt > 0 && time.Unix(validAt, 0).After(now) {
		return fmt.Errorf("intent message not valid yet")
	}

	return nil
}
