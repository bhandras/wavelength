package waved

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/wavelength/baselib/actor"
	"github.com/lightninglabs/wavelength/chainsource"
	"github.com/lightninglabs/wavelength/internal/expiryfixture"
	"github.com/lightninglabs/wavelength/lib/arkscript"
	"github.com/lightninglabs/wavelength/lib/tree"
	"github.com/lightninglabs/wavelength/vtxo"
	fn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/stretchr/testify/require"
)

type testChainFuture = actor.Future[chainsource.ChainSourceResp]

// TestIndexedExpiryReadBoundsSilentConfirmation proves a stale positive height
// hint cannot turn a read into the durable 30-second confirmation wait. The
// valid output survives without a deadline and the one-shot watch is removed.
func TestIndexedExpiryReadBoundsSilentConfirmation(t *testing.T) {
	t.Parallel()

	indexed, _ := expiryfixture.Round(
		t, 10_000, []byte{0x51}, 50, 100, 1,
	)
	chainSource := &blockingExpiryChainSource{
		unregistered: make(chan struct{}, 1),
	}
	start := time.Now()
	verified, err := authenticateIndexedExpiry(
		t.Context(), indexed, NewBatchExpiryAuthenticator(chainSource),
	)
	require.NoError(t, err)
	require.Zero(t, verified.batchExpiry)
	require.Positive(t, verified.treeDepth)
	require.Less(t, time.Since(start), 5*time.Second)
	select {
	case <-chainSource.unregistered:
	default:
		t.Fatal("read left a confirmation watch registered")
	}
}

// TestBatchExpiryAuthenticatorTimesOut verifies that a confirmation backend
// which never resolves releases the durable caller for retry and unregisters
// its one-shot watch.
func TestBatchExpiryAuthenticatorTimesOut(t *testing.T) {
	t.Parallel()

	chainSource := &blockingExpiryChainSource{
		unregistered: make(chan struct{}, 1),
	}
	authenticate := batchExpiryAuthenticatorWithTimeout(
		chainSource, 10*time.Millisecond,
	)

	_, err := authenticate(t.Context(), []vtxo.Ancestry{
		testExpiryAuthenticationAncestry(t),
	})
	require.ErrorIs(t, err, context.DeadlineExceeded)

	select {
	case <-chainSource.unregistered:
	case <-time.After(time.Second):
		t.Fatal("confirmation watch was not unregistered")
	}
}

// TestBatchExpiryAuthenticatorRegistrationTimeoutUnregisters proves cleanup
// is armed before the registration Ask resolves. The chain-source actor may
// still create the watch after the caller's deadline.
func TestBatchExpiryAuthenticatorRegistrationTimeoutUnregisters(t *testing.T) {
	t.Parallel()

	chainSource := &blockingExpiryChainSource{
		unregistered:        make(chan struct{}, 1),
		registrationBlocked: true,
	}
	authenticate := batchExpiryAuthenticatorWithTimeout(
		chainSource, 10*time.Millisecond,
	)

	_, err := authenticate(t.Context(), []vtxo.Ancestry{
		testExpiryAuthenticationAncestry(t),
	})
	require.ErrorIs(t, err, context.DeadlineExceeded)

	select {
	case <-chainSource.unregistered:
	case <-time.After(time.Second):
		t.Fatal("timed-out registration was not unregistered")
	}
}

type blockingExpiryChainSource struct {
	unregistered        chan struct{}
	registrationBlocked bool
}

// ID supplies a stable identity for the confirmation actor stub.
func (b *blockingExpiryChainSource) ID() string {
	return "blocking-expiry-chain-source"
}

// Tell records confirmation-watch cleanup requests.
func (b *blockingExpiryChainSource) Tell(_ context.Context,
	msg chainsource.ChainSourceMsg) error {

	if _, ok := msg.(*chainsource.UnregisterConfRequest); ok {
		select {
		case b.unregistered <- struct{}{}:
		default:
		}
	}

	return nil
}

// TryTell delegates nonblocking test delivery to Tell.
func (b *blockingExpiryChainSource) TryTell(ctx context.Context,
	msg chainsource.ChainSourceMsg) error {

	return b.Tell(ctx, msg)
}

// Ask supplies the scripted one-shot confirmation registration.
func (b *blockingExpiryChainSource) Ask(_ context.Context,
	msg chainsource.ChainSourceMsg) testChainFuture {

	response := actor.NewPromise[chainsource.ChainSourceResp]()
	if _, ok := msg.(*chainsource.RegisterConfRequest); !ok {
		response.Complete(
			fn.Err[chainsource.ChainSourceResp](
				fmt.Errorf("unexpected request %T", msg),
			),
		)

		return response.Future()
	}
	if b.registrationBlocked {
		return response.Future()
	}

	confirmation := actor.NewPromise[chainsource.ConfirmationEvent]()
	response.Complete(
		fn.Ok[chainsource.ChainSourceResp](
			&chainsource.RegisterConfResponse{
				Future: confirmation.Future(),
			},
		),
	)

	return response.Future()
}

// testExpiryAuthenticationAncestry constructs sweep evidence for testing
// bounded chain waits and cleanup independently of target-proof validation.
func testExpiryAuthenticationAncestry(t *testing.T) vtxo.Ancestry {
	t.Helper()

	const delay = uint32(144)
	sweepKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	sweepLeaf, err := arkscript.UnilateralCSVTimeoutTapLeaf(
		sweepKey.PubKey(), delay,
	)
	require.NoError(t, err)
	sweepRoot := sweepLeaf.TapHash()
	ownerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	cosigners := []*btcec.PublicKey{ownerKey.PubKey()}
	finalKey, err := tree.ComputeFinalKey(cosigners, sweepRoot[:])
	require.NoError(t, err)
	batchScript, err := txscript.PayToTaprootScript(finalKey)
	require.NoError(t, err)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{1}},
	})
	tx.AddTxOut(&wire.TxOut{
		Value:    10_000,
		PkScript: batchScript,
	})
	txid := tx.TxHash()

	return vtxo.Ancestry{
		TreePath: &tree.Tree{
			Root: &tree.Node{
				CoSigners: cosigners,
			},
			BatchOutpoint: wire.OutPoint{
				Hash: txid,
			},
			BatchOutput:        tx.TxOut[0],
			SweepTapscriptRoot: sweepRoot[:],
		},
		CommitmentTxID:       txid,
		CommitmentHeight:     100,
		CommitmentSweepDelay: delay,
		CommitmentSweepKey:   sweepKey.PubKey(),
	}
}
