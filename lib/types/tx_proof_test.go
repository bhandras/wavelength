package types

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

// TestTxMerkleProof checks every position across balanced and unbalanced trees
// against btcd's independently constructed block merkle root.
func TestTxMerkleProof(t *testing.T) {
	t.Parallel()

	var txs []*wire.MsgTx
	var blockTxs []*btcutil.Tx
	for count := 1; count <= 40; count++ {
		txn := wire.NewMsgTx(2)
		txn.AddTxIn(
			wire.NewTxIn(
				&wire.OutPoint{
					Hash: chainhash.Hash{byte(count)},
				},
				nil,
				nil,
			),
		)
		txn.AddTxOut(
			wire.NewTxOut(
				int64(count), []byte{txscript.OP_TRUE},
			),
		)
		txs = append(txs, txn)
		blockTxs = append(blockTxs, btcutil.NewTx(txn))
		tree := blockchain.BuildMerkleTreeStore(blockTxs, false)
		root := *tree[len(tree)-1]
		for idx := range txs {
			proof, err := NewTxMerkleProof(txs, idx)
			require.NoError(t, err)
			require.True(t, proof.Verify(txs[idx], root))
			require.False(
				t,
				proof.Verify(
					txs[idx], chainhash.Hash{},
				),
			)

			var encoded bytes.Buffer
			require.NoError(t, proof.Encode(&encoded))
			var decoded TxMerkleProof
			require.NoError(t, decoded.Decode(&encoded))
			require.Equal(t, *proof, decoded)
		}
	}
}

// TestTxMerkleProofWireEncoding pins the pre-existing boarding proof format.
func TestTxMerkleProofWireEncoding(t *testing.T) {
	t.Parallel()

	proof := TxMerkleProof{
		Nodes: []chainhash.Hash{
			{
				1,
			},
			{
				2,
			},
		},
		Bits: []bool{
			true,
			false,
		},
	}
	want, err := hex.DecodeString(
		"02010000000000000000000000000000000000000000000000000000000" +
			"000000002000000000000000000000000000000000000000000" +
			"0000000000000000000001",
	)
	require.NoError(t, err)
	var encoded bytes.Buffer
	require.NoError(t, proof.Encode(&encoded))
	require.Equal(t, want, encoded.Bytes())

	for end := range want {
		decoded := TxMerkleProof{
			Nodes: []chainhash.Hash{
				{
					9,
				},
			},
			Bits: []bool{
				false,
			},
		}
		original := decoded
		require.Error(t, decoded.Decode(bytes.NewReader(want[:end])))
		require.Equal(t, original, decoded)
	}
	var decoded TxMerkleProof
	require.ErrorIs(
		t,
		decoded.Decode(
			bytes.NewReader(
				[]byte{16},
			),
		),
		tlv.ErrRecordTooLarge,
	)

	proof.Bits = nil
	require.Error(t, proof.Encode(&encoded))
	require.False(t, proof.Verify(wire.NewMsgTx(2), chainhash.Hash{}))
	_, err = NewTxMerkleProof([]*wire.MsgTx{wire.NewMsgTx(2)}, -1)
	require.Error(t, err)
	_, err = NewTxMerkleProof([]*wire.MsgTx{nil}, 0)
	require.Error(t, err)
}

// TestTxProofVerification checks that inclusion cannot authenticate a different
// output or bypass the caller's chain-header verifier.
func TestTxProofVerification(t *testing.T) {
	t.Parallel()

	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	script, err := txscript.PayToTaprootScript(
		txscript.ComputeTaprootKeyNoScript(
			key.PubKey(),
		),
	)
	require.NoError(t, err)
	txn := wire.NewMsgTx(2)
	txn.AddTxIn(
		wire.NewTxIn(
			&wire.OutPoint{
				Hash: chainhash.Hash{1},
			},
			nil,
			nil,
		),
	)
	txn.AddTxOut(wire.NewTxOut(1_000, script))
	proof := &TxProof{
		MsgTx: *txn,
		BlockHeader: wire.BlockHeader{
			MerkleRoot: txn.TxHash(),
		},
		BlockHeight: 42,
		ClaimedOutPoint: wire.OutPoint{
			Hash: txn.TxHash(),
		},
		InternalKey: *key.PubKey(),
	}
	headerChecked := false
	verifyHeader := func(header wire.BlockHeader, height uint32) error {
		headerChecked = true
		require.EqualValues(t, 42, height)
		require.Equal(t, txn.TxHash(), header.MerkleRoot)

		return nil
	}
	require.NoError(t, proof.Verify(verifyHeader, DefaultMerkleVerifier))
	require.True(t, headerChecked)

	headerChecked = false
	proof.ClaimedOutPoint.Hash[0] ^= 1
	require.Error(t, proof.Verify(verifyHeader, DefaultMerkleVerifier))
	require.False(t, headerChecked)
	proof.ClaimedOutPoint.Hash = txn.TxHash()
	proof.BlockHeader.MerkleRoot[0] ^= 1
	require.Error(t, proof.Verify(verifyHeader, DefaultMerkleVerifier))
	require.False(t, headerChecked)
}
