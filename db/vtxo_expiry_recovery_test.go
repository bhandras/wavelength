package db

import (
	"math"
	"testing"

	"github.com/lightninglabs/wavelength/vtxo"
	"github.com/stretchr/testify/require"
)

// TestRecoveredVTXOExpiryIgnoresCreatedHeight verifies existing wallet rows
// with overstated creation metadata still enter unilateral exit when their
// authenticated batch deadline becomes critical.
func TestRecoveredVTXOExpiryIgnoresCreatedHeight(t *testing.T) {
	t.Parallel()

	store, _, _ := newVTXOStoreForTest(t)
	desc := createTestVTXODescriptor(
		t, testRoundIDDB("expiry-recovery"), 0,
	)
	desc.CreatedHeight = math.MaxInt32
	require.NoError(t, store.SaveVTXO(t.Context(), desc))

	// Recover through the same store listing used at daemon startup. The
	// fix must protect old rows without rewriting their historical fields.
	recovered, err := store.ListRecoverableVTXOs(t.Context())
	require.NoError(t, err)
	require.Len(t, recovered, 1)
	require.Equal(t, int32(math.MaxInt32), recovered[0].CreatedHeight)

	cfg := vtxo.DefaultExpiryConfig()
	child := vtxo.NewVTXOActor(t.Context(), &vtxo.VTXOActorConfig{
		VTXO:         recovered[0],
		Store:        store,
		ExpiryConfig: cfg,
	})
	require.IsType(t, &vtxo.LiveState{}, child.CurrentState())

	criticalBlocks := cfg.CalculateCriticalThreshold(recovered[0])
	response, err := child.Receive(t.Context(), &vtxo.BlockEpochEvent{
		Height: recovered[0].BatchExpiry - criticalBlocks,
	}).Unpack()
	require.NoError(t, err)
	require.IsType(t, &vtxo.UnilateralExitState{}, child.CurrentState())

	result, ok := response.(vtxo.VTXOActorResponse)
	require.True(t, ok)
	var notifications []*vtxo.ExpiringNotification
	for _, message := range result.Outbox {
		notification, ok := message.(*vtxo.ExpiringNotification)
		if ok {
			notifications = append(notifications, notification)
		}
	}
	require.Len(t, notifications, 1)
	require.Equal(t, desc.Outpoint, notifications[0].VTXO.Outpoint)
	require.Equal(t, criticalBlocks, notifications[0].BlocksRemaining)

	stored, err := store.GetVTXO(t.Context(), desc.Outpoint)
	require.NoError(t, err)
	require.Equal(t, vtxo.VTXOStatusUnilateralExit, stored.Status)
	require.Equal(t, desc.CreatedHeight, stored.CreatedHeight)
}
