//go:build wavewalletrpc && swapruntime

package swapwallet

// Regression matrix for issue #1464: an internal swap funding OOR leg
// whose swap record never persisted its funding session id surfaced as a
// phantom ledger-N SEND that no restart could reconcile away. Each case
// builds one production shape and asserts whether the send row is hidden,
// covering the structured swap correlation, the keyed (idempotency)
// correlation added as the fix, and the documented hard boundaries.

import (
	"context"
	"strings"
	"testing"

	"github.com/lightninglabs/wavelength/ledger"
	"github.com/lightninglabs/wavelength/rpc/swapclientrpc"
	"github.com/lightninglabs/wavelength/rpc/wavewalletrpc"
	"github.com/lightninglabs/wavelength/waverpc"
	"github.com/stretchr/testify/require"
)

// visibleSendIDs returns the ids of all visible SEND entries.
func visibleSendIDs(t *testing.T, h *history) []string {
	t.Helper()

	resp, err := h.List(t.Context(), &wavewalletrpc.ListRequest{})
	require.NoError(t, err)

	var ids []string
	for _, e := range resp.GetActivity().GetEntries() {
		if e.GetKind() == wavewalletrpc.EntryKind_ENTRY_KIND_SEND {
			ids = append(ids, e.GetId())
		}
	}

	return ids
}

func paySwapSummary(sessionHex string, amount int64) *swapclientrpc.SwapSummary {
	return &swapclientrpc.SwapSummary{
		PaymentHash:      "payment-hash",
		Direction:        swapclientrpc.SwapDirection_SWAP_DIRECTION_PAY,
		State:            swapclientrpc.SwapState_SWAP_STATE_COMPLETED,
		AmountSat:        amount,
		UpdatedAtUnix:    200,
		FundingSessionId: sessionHex,
	}
}

func fundingSendRow(session []byte, amount, entryID int64) *waverpc.TransactionHistoryEntry {
	return &waverpc.TransactionHistoryEntry{
		Type:               "oor",
		Subtype:            ledger.EventVTXOSent,
		ConfirmationStatus: "recorded",
		AmountSat:          amount,
		DebitAccount:       ledger.AccountTransfersOut,
		CreditAccount:      ledger.AccountVTXOBalance,
		SessionId:          session,
		EntryId:            entryID,
		CreatedAtUnixS:     100,
	}
}

// Case A (control): exact-input funding, no change. Covered by existing
// tests; expected hidden.
func TestIssue1464CaseAExactInput(t *testing.T) {
	t.Parallel()

	h, swap, rpc := newHistoryFixture(t)
	sessionID := testBytes(32, 0x31)
	sessionHex := testSessionString(t, sessionID)

	swap.listSwapsResp = &swapclientrpc.ListSwapsResponse{
		Swaps: []*swapclientrpc.SwapSummary{
			paySwapSummary(sessionHex, 12_233),
		},
	}
	rpc.listTxResp = &waverpc.ListTransactionsResponse{
		Transactions: []*waverpc.TransactionHistoryEntry{
			fundingSendRow(sessionID, 12_233, 138),
		},
	}

	require.NotContains(t, visibleSendIDs(t, h), "ledger-138")
}

// Case B: funding with change, but the change receive row is keyed by the
// REAL OOR txid (e.g. re-keyed after the tx finalizes) instead of the
// session id. Expectation: hidden; suspicion: LEAK at gross amount.
func TestIssue1464CaseBChangeKeyedByRealTxid(t *testing.T) {
	t.Parallel()

	h, swap, rpc := newHistoryFixture(t)
	sessionID := testBytes(32, 0x32)
	sessionHex := testSessionString(t, sessionID)

	swap.listSwapsResp = &swapclientrpc.ListSwapsResponse{
		Swaps: []*swapclientrpc.SwapSummary{
			paySwapSummary(sessionHex, 12_233),
		},
	}
	rpc.listTxResp = &waverpc.ListTransactionsResponse{
		Transactions: []*waverpc.TransactionHistoryEntry{
			fundingSendRow(sessionID, 15_000, 138),
			{
				Type:               "oor",
				Subtype:            ledger.EventVTXOReceived,
				ConfirmationStatus: "recorded",
				AmountSat:          2_767,
				DebitAccount:       ledger.AccountVTXOBalance,
				CreditAccount:      ledger.AccountTransfersIn,
				// Real txid, NOT the session id.
				Txid: "aa55aa55aa55aa55aa55aa55aa55aa55" +
					"aa55aa55aa55aa55aa55aa55aa55aa55",
				OutputIndex:    1,
				EntryId:        139,
				CreatedAtUnixS: 101,
			},
		},
	}

	// Known limitation, documented: not a current production shape (both
	// receive-booking sites always set SessionID), but if a change row
	// ever loses its session id the gross send leaks.
	require.Contains(t, visibleSendIDs(t, h), "ledger-138")
}

// Case C: swap summary lacks FundingSessionId (crash between funding and
// persistFundingResult, or the same-Ark empty-outpoint path) and no
// dispatch-key dep is wired. Expectation: LEAK, matching legacy behavior.
func TestIssue1464CaseCMissingFundingSession(t *testing.T) {
	t.Parallel()

	h, swap, rpc := newHistoryFixture(t)
	sessionID := testBytes(32, 0x33)

	swap.listSwapsResp = &swapclientrpc.ListSwapsResponse{
		Swaps: []*swapclientrpc.SwapSummary{
			paySwapSummary("", 12_233),
		},
	}
	rpc.listTxResp = &waverpc.ListTransactionsResponse{
		Transactions: []*waverpc.TransactionHistoryEntry{
			fundingSendRow(sessionID, 12_233, 138),
		},
	}

	require.Contains(t, visibleSendIDs(t, h), "ledger-138")
}

// fakeOORDispatch is an OORDispatchLookup fake keyed by session id string.
type fakeOORDispatch struct {
	keys map[string]string
	err  error
}

func (f *fakeOORDispatch) DispatchIdempotencyKey(_ context.Context,
	sessionID string) (string, error) {

	if f.err != nil {
		return "", f.err
	}

	return f.keys[sessionID], nil
}

// Case C-fixed: the swap record lacks FundingSessionId, but the dispatch
// registry resolves the send's idempotency key naming the swap's payment
// hash. The keyed correlation must hide the row.
func TestIssue1464CaseCFixedByDispatchKey(t *testing.T) {
	t.Parallel()

	h, swap, rpc := newHistoryFixture(t)
	sessionID := testBytes(32, 0x36)
	sessionHex := testSessionString(t, sessionID)
	payHash := strings.Repeat("ab", 32)

	swap.listSwapsResp = &swapclientrpc.ListSwapsResponse{
		Swaps: []*swapclientrpc.SwapSummary{
			{
				PaymentHash:   payHash,
				Direction:     swapclientrpc.SwapDirection_SWAP_DIRECTION_PAY,
				State:         swapclientrpc.SwapState_SWAP_STATE_COMPLETED,
				AmountSat:     12_233,
				UpdatedAtUnix: 200,
				// FundingSessionId deliberately empty.
			},
		},
	}
	rpc.listTxResp = &waverpc.ListTransactionsResponse{
		Transactions: []*waverpc.TransactionHistoryEntry{
			fundingSendRow(sessionID, 12_233, 138),
		},
	}
	h.deps.OORDispatch = &fakeOORDispatch{
		keys: map[string]string{
			sessionHex: "in-swap-funding:" + payHash,
		},
	}

	require.NotContains(t, visibleSendIDs(t, h), "ledger-138")
}

// Case C-negative: the dispatch key names a payment hash with no matching
// pay swap, so the row must stay visible (raw user sends with caller keys
// are never hidden by keyed correlation).
func TestIssue1464CaseCUnknownSwapStaysVisible(t *testing.T) {
	t.Parallel()

	h, swap, rpc := newHistoryFixture(t)
	sessionID := testBytes(32, 0x37)
	sessionHex := testSessionString(t, sessionID)

	swap.listSwapsResp = &swapclientrpc.ListSwapsResponse{}
	rpc.listTxResp = &waverpc.ListTransactionsResponse{
		Transactions: []*waverpc.TransactionHistoryEntry{
			fundingSendRow(sessionID, 12_233, 138),
		},
	}
	h.deps.OORDispatch = &fakeOORDispatch{
		keys: map[string]string{
			sessionHex: "in-swap-funding:" + strings.Repeat("cd", 32),
		},
	}

	require.Contains(t, visibleSendIDs(t, h), "ledger-138")
}

// Case D: swap record absent from ListSwaps entirely. Both correlation
// channels need the swap record (session id or payment hash), so this
// stays visible; documented as a hard boundary of the design, not a bug.
func TestIssue1464CaseDSwapAbsent(t *testing.T) {
	t.Parallel()

	h, swap, rpc := newHistoryFixture(t)
	sessionID := testBytes(32, 0x34)

	swap.listSwapsResp = &swapclientrpc.ListSwapsResponse{}
	rpc.listTxResp = &waverpc.ListTransactionsResponse{
		Transactions: []*waverpc.TransactionHistoryEntry{
			fundingSendRow(sessionID, 12_233, 138),
		},
	}

	require.Contains(t, visibleSendIDs(t, h), "ledger-138")
}

// Case E: exact liongrass shape — single send, no change, swap registered
// and completed, amount matches, session matches. Differs from Case A only
// in swap state/timing semantics. Control for "should work".
func TestIssue1464CaseELiongrassShape(t *testing.T) {
	t.Parallel()

	h, swap, rpc := newHistoryFixture(t)
	sessionID := testBytes(32, 0x35)
	sessionHex := testSessionString(t, sessionID)

	swap.listSwapsResp = &swapclientrpc.ListSwapsResponse{
		Swaps: []*swapclientrpc.SwapSummary{
			paySwapSummary(sessionHex, 12_233),
		},
	}
	rpc.listTxResp = &waverpc.ListTransactionsResponse{
		Transactions: []*waverpc.TransactionHistoryEntry{
			fundingSendRow(sessionID, 12_233, 138),
		},
	}

	sends := visibleSendIDs(t, h)
	t.Logf("visible sends: %v", sends)
	require.NotContains(t, sends, "ledger-138")
}
