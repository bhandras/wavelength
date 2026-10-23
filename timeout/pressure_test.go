package timeout

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/lightninglabs/wavelength/baselib/actor"
	"github.com/stretchr/testify/require"
)

// TestMailboxPressureEpisode covers the grace boundary, episode deduplication,
// wrapped queue errors, and a changed failure that must remain visible.
func TestMailboxPressureEpisode(t *testing.T) {
	t.Parallel()

	var pressure mailboxPressure
	full := fmt.Errorf("enqueue: %w", actor.ErrMailboxFull)
	require.False(t, pressure.shouldWarn(startEpoch, full))
	require.False(
		t,
		pressure.shouldWarn(
			startEpoch.Add(mailboxPressureGrace-time.Nanosecond),
			full,
		),
	)
	require.True(
		t,
		pressure.shouldWarn(
			startEpoch.Add(mailboxPressureGrace), full,
		),
	)
	require.False(t, pressure.shouldWarn(startEpoch.Add(time.Hour), full))

	for _, err := range []error{
		context.DeadlineExceeded, actor.ErrNoActorsAvailable,
		errors.New("mailbox full"), errors.New("connection reset"),
	} {
		require.True(
			t,
			pressure.shouldWarn(
				startEpoch.Add(time.Hour), err,
			),
		)
		require.Zero(t, pressure)
	}

	// A later full-mailbox episode must earn its own grace and warning.
	now := startEpoch.Add(2 * time.Hour)
	require.False(t, pressure.shouldWarn(now, full))
	require.True(
		t,
		pressure.shouldWarn(
			now.Add(mailboxPressureGrace), full,
		),
	)
}

// TestTimeoutPressureRecovery retains a burst of independent cleanup messages
// across brief or sustained queue pressure, then delivers each exactly once.
func TestTimeoutPressureRecovery(t *testing.T) {
	t.Parallel()

	for _, blocked := range []time.Duration{time.Second, time.Minute} {
		t.Run(blocked.String(), func(t *testing.T) {
			t.Parallel()

			clock := newFakeClock(startEpoch)
			a := newTestActor(clock)
			cb := newWedgeableCallbackRef(
				"manager", actor.ErrMailboxFull,
			)
			for i := range 12 {
				result := a.Receive(
					t.Context(), &ScheduleTimeoutRequest{
						ID: ID(
							fmt.Sprintf(
								"cleanup-%d",
								i),
						),
						Duration: time.Millisecond,
						Callback: cb,
					},
				)
				require.True(t, result.IsOk())
			}

			clock.Advance(blocked)
			require.Len(t, a.oneshots, 12)
			for _, entry := range a.oneshots {
				require.Equal(
					t, blocked >= mailboxPressureGrace,
					entry.pressure.warned,
				)
			}

			cb.release()
			clock.Advance(retryMaxDelay)
			msgs, _ := cb.snapshot()
			require.Len(t, msgs, 12)
			ids := make(map[ID]bool)
			for _, msg := range msgs {
				require.False(
					t, ids[msg.ID], "duplicate delivery",
				)
				ids[msg.ID] = true
			}
			require.Empty(t, a.oneshots)
		})
	}
}
