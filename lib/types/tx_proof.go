package types

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightningnetwork/lnd/tlv"
)

// MaxTxMerkleProofNodes bounds Bitcoin transaction inclusion proofs. Fifteen
// levels cover the maximum number of transactions in a consensus-valid block.
const MaxTxMerkleProofNodes = 15

// HeaderVerifier authenticates a block header at its claimed chain height.
type HeaderVerifier func(wire.BlockHeader, uint32) error

// MerkleVerifier authenticates a transaction against a block's merkle root.
type MerkleVerifier func(*wire.MsgTx, *TxMerkleProof, [32]byte) error

// TxMerkleProof proves the inclusion of one transaction in a Bitcoin block.
// The encoding is the existing boarding protocol's node count, sibling hashes,
// and packed direction bits, in that order.
type TxMerkleProof struct {
	// Nodes contains the siblings from the transaction up to the root.
	Nodes []chainhash.Hash

	// Bits is true when the corresponding sibling is on the right.
	Bits []bool
}

// NewTxMerkleProof constructs an inclusion proof using Bitcoin's duplicate-last
// rule for levels with an odd number of nodes.
func NewTxMerkleProof(txs []*wire.MsgTx, txIdx int) (*TxMerkleProof, error) {
	if txIdx < 0 || txIdx >= len(txs) {
		return nil, fmt.Errorf("transaction index %d is out of range",
			txIdx)
	}
	if len(txs) > 1<<MaxTxMerkleProofNodes {
		return nil, fmt.Errorf("too many transactions for inclusion " +
			"proof")
	}

	level := make([]chainhash.Hash, len(txs))
	for idx, txn := range txs {
		if txn == nil {
			return nil, fmt.Errorf("transaction %d is nil", idx)
		}
		level[idx] = txn.TxHash()
	}

	proof := &TxMerkleProof{
		Nodes: make([]chainhash.Hash, 0),
		Bits:  make([]bool, 0),
	}
	for len(level) > 1 {
		sibling := txIdx ^ 1
		if sibling >= len(level) {
			sibling = txIdx
		}
		proof.Nodes = append(proof.Nodes, level[sibling])
		proof.Bits = append(proof.Bits, txIdx%2 == 0)

		next := make([]chainhash.Hash, (len(level)+1)/2)
		for idx := range next {
			left, right := 2*idx, 2*idx+1
			if right == len(level) {
				right = left
			}
			next[idx] = hashMerklePair(level[left], level[right])
		}
		level = next
		txIdx /= 2
	}

	return proof, nil
}

// hashMerklePair hashes a left and right child in Bitcoin's merkle tree.
func hashMerklePair(left, right chainhash.Hash) chainhash.Hash {
	var pair [2 * chainhash.HashSize]byte
	copy(pair[:chainhash.HashSize], left[:])
	copy(pair[chainhash.HashSize:], right[:])

	return chainhash.DoubleHashH(pair[:])
}

// Verify checks the transaction's inclusion in the supplied merkle root.
func (p *TxMerkleProof) Verify(txn *wire.MsgTx, root chainhash.Hash) bool {
	if p == nil || txn == nil || len(p.Nodes) != len(p.Bits) ||
		len(p.Nodes) > MaxTxMerkleProofNodes {
		return false
	}

	current := txn.TxHash()
	for idx, sibling := range p.Nodes {
		if p.Bits[idx] {
			current = hashMerklePair(current, sibling)
		} else {
			current = hashMerklePair(sibling, current)
		}
	}

	return current == root
}

// Encode writes the boarding protocol's transaction inclusion proof encoding.
func (p *TxMerkleProof) Encode(w io.Writer) error {
	if p == nil || len(p.Nodes) != len(p.Bits) ||
		len(p.Nodes) > MaxTxMerkleProofNodes {
		return fmt.Errorf("invalid transaction merkle proof shape")
	}
	var scratch [8]byte
	if err := tlv.WriteVarInt(
		w,
		uint64(
			len(p.Nodes),
		),
		&scratch,
	); err != nil {
		return err
	}
	for _, node := range p.Nodes {
		if _, err := w.Write(node[:]); err != nil {
			return err
		}
	}

	packed := make([]byte, (len(p.Bits)+7)/8)
	for idx, right := range p.Bits {
		if right {
			packed[idx/8] |= 1 << (idx % 8)
		}
	}
	_, err := w.Write(packed)

	return err
}

// Decode reads a bounded inclusion proof without replacing the receiver when
// the input is truncated or malformed.
func (p *TxMerkleProof) Decode(r io.Reader) error {
	var scratch [8]byte
	count, err := tlv.ReadVarInt(r, &scratch)
	if err != nil {
		return err
	}
	if count > MaxTxMerkleProofNodes {
		return tlv.ErrRecordTooLarge
	}

	nodes := make([]chainhash.Hash, int(count))
	for idx := range nodes {
		if _, err := io.ReadFull(r, nodes[idx][:]); err != nil {
			return err
		}
	}
	packed := make([]byte, (count+7)/8)
	if _, err := io.ReadFull(r, packed); err != nil {
		return err
	}
	bits := make([]bool, int(count))
	for idx := range bits {
		bits[idx] = packed[idx/8]&(1<<(idx%8)) != 0
	}
	p.Nodes, p.Bits = nodes, bits

	return nil
}

// TxProof binds a boarding outpoint to a transaction, a block, and the Taproot
// construction of the claimed output. It contains no Taproot Asset state.
type TxProof struct {
	MsgTx           wire.MsgTx
	BlockHeader     wire.BlockHeader
	BlockHeight     uint32
	MerkleProof     TxMerkleProof
	ClaimedOutPoint wire.OutPoint
	InternalKey     btcec.PublicKey
	MerkleRoot      []byte
}

// Verify authenticates the claimed output, merkle inclusion, and block header.
func (p *TxProof) Verify(headerVerifier HeaderVerifier,
	merkleVerifier MerkleVerifier) error {

	if p == nil || headerVerifier == nil || merkleVerifier == nil {
		return errors.New("transaction proof and verifiers are " +
			"required")
	}
	if p.ClaimedOutPoint.Hash != p.MsgTx.TxHash() {
		return errors.New("outpoint hash does not match transaction " +
			"hash")
	}
	if p.ClaimedOutPoint.Index >= uint32(len(p.MsgTx.TxOut)) {
		return errors.New("claimed output index is out of range")
	}
	if len(p.MerkleRoot) != 0 && len(p.MerkleRoot) != chainhash.HashSize {
		return errors.New("invalid Taproot merkle root length")
	}
	if !p.InternalKey.IsOnCurve() {
		return errors.New("invalid Taproot internal key")
	}
	outputKey := txscript.ComputeTaprootOutputKey(
		&p.InternalKey, p.MerkleRoot,
	)
	expected, err := txscript.PayToTaprootScript(outputKey)
	if err != nil {
		return err
	}
	output := p.MsgTx.TxOut[p.ClaimedOutPoint.Index]
	if output == nil || !bytes.Equal(output.PkScript, expected) {
		return errors.New("claimed output does not match Taproot " +
			"construction")
	}
	if err := merkleVerifier(
		&p.MsgTx, &p.MerkleProof, p.BlockHeader.MerkleRoot,
	); err != nil {
		return err
	}

	return headerVerifier(p.BlockHeader, p.BlockHeight)
}

// DefaultMerkleVerifier checks Bitcoin transaction inclusion against a root.
func DefaultMerkleVerifier(txn *wire.MsgTx, proof *TxMerkleProof,
	root [32]byte) error {

	if proof == nil || !proof.Verify(txn, root) {
		return errors.New("invalid transaction merkle proof")
	}

	return nil
}
