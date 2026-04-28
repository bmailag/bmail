//go:build js && wasm

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"syscall/js"
)

// ── Key Transparency ────────────────────────────────────────

func verifyKTProof(args []js.Value) (interface{}, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("verifyKTProof requires 1 arg: proofJSON")
	}
	proofJSON := args[0].String()

	var proof struct {
		LeafHash    string   `json:"leaf_hash"`
		RootHash    string   `json:"root_hash"`
		Proof       []string `json:"proof"`
		LeafIndex   int      `json:"leaf_index"`
		TotalLeaves int      `json:"total_leaves"`
	}
	if err := json.Unmarshal([]byte(proofJSON), &proof); err != nil {
		return nil, fmt.Errorf("parse proof: %w", err)
	}

	leafHash, err := unb64(proof.LeafHash)
	if err != nil {
		return nil, fmt.Errorf("decode leaf_hash: %w", err)
	}
	rootHash, err := unb64(proof.RootHash)
	if err != nil {
		return nil, fmt.Errorf("decode root_hash: %w", err)
	}

	siblings := make([][]byte, len(proof.Proof))
	for i, s := range proof.Proof {
		siblings[i], err = unb64(s)
		if err != nil {
			return nil, fmt.Errorf("decode proof[%d]: %w", i, err)
		}
	}

	valid := verifyMerkleProof(leafHash, rootHash, siblings, proof.LeafIndex, proof.TotalLeaves)
	return valid, nil
}

// verifyMerkleProof checks that leafHash combined with the proof produces rootHash.
// Mirrors kt.VerifyInclusionProof without importing the kt package (which pulls in storage deps).
func verifyMerkleProof(leafHash, rootHash []byte, proof [][]byte, leafIndex, totalLeaves int) bool {
	if totalLeaves <= 0 {
		return false
	}
	current := make([]byte, len(leafHash))
	copy(current, leafHash)
	idx := leafIndex
	for _, sibling := range proof {
		h := sha256.New()
		h.Write([]byte{0x01}) // RFC 6962 internal node domain separation
		if idx%2 == 0 {
			h.Write(current)
			h.Write(sibling)
		} else {
			h.Write(sibling)
			h.Write(current)
		}
		current = h.Sum(nil)
		idx /= 2
	}
	return subtle.ConstantTimeCompare(current, rootHash) == 1
}

// verifyMyKey verifies a full KT proof for the user's key: inclusion proof + root signature.
// Args: proofJSON (contains leaf_hash, root_hash, proof, leaf_index, total_leaves, signature),
//
//	ktSigningPubKey (base64 Ed25519 public key of the KT service)
//
// Returns true if both the Merkle inclusion proof and the root signature are valid.
func verifyMyKey(args []js.Value) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("verifyMyKey requires 2 args: proofJSON, ktSigningPubKey")
	}
	proofJSON := args[0].String()
	ktPubKeyB64 := args[1].String()

	var proof struct {
		LeafHash    string   `json:"leaf_hash"`
		RootHash    string   `json:"root_hash"`
		Proof       []string `json:"proof"`
		LeafIndex   int      `json:"leaf_index"`
		TotalLeaves int      `json:"total_leaves"`
		Epoch       uint64   `json:"epoch"`
		Signature   string   `json:"signature"`
	}
	if err := json.Unmarshal([]byte(proofJSON), &proof); err != nil {
		return nil, fmt.Errorf("parse proof: %w", err)
	}

	leafHash, err := unb64(proof.LeafHash)
	if err != nil {
		return nil, fmt.Errorf("decode leaf_hash: %w", err)
	}
	rootHash, err := unb64(proof.RootHash)
	if err != nil {
		return nil, fmt.Errorf("decode root_hash: %w", err)
	}
	signature, err := unb64(proof.Signature)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	ktPubKey, err := unb64(ktPubKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decode ktSigningPubKey: %w", err)
	}

	if len(ktPubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid KT signing public key length: %d", len(ktPubKey))
	}

	siblings := make([][]byte, len(proof.Proof))
	for i, s := range proof.Proof {
		siblings[i], err = unb64(s)
		if err != nil {
			return nil, fmt.Errorf("decode proof[%d]: %w", i, err)
		}
	}

	// Step 1: Verify the Merkle inclusion proof.
	if !verifyMerkleProof(leafHash, rootHash, siblings, proof.LeafIndex, proof.TotalLeaves) {
		return false, nil
	}

	// Step 2: Verify the root signature (Ed25519).
	// Reconstruct the same structured message the server signs:
	// "bmail-kt-root-v1:" || epoch (8 bytes BE) || treeSize (8 bytes BE) || rootHash
	var rootMsg []byte
	rootMsg = append(rootMsg, []byte("bmail-kt-root-v1:")...)
	epochBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(epochBuf, proof.Epoch)
	rootMsg = append(rootMsg, epochBuf...)
	sizeBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(sizeBuf, uint64(proof.TotalLeaves))
	rootMsg = append(rootMsg, sizeBuf...)
	rootMsg = append(rootMsg, rootHash...)
	if !ed25519.Verify(ed25519.PublicKey(ktPubKey), rootMsg, signature) {
		return false, nil
	}

	return true, nil
}
