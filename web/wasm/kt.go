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

// uuidBytes parses a canonical UUID string (8-4-4-4-12 hex, dashes optional)
// into its 16 raw bytes, matching Go's uuid.UUID[:] layout. This lets the WASM
// group-leaf hash bind to the same group_id bytes the server hashed.
func uuidBytes(s string) ([]byte, error) {
	out := make([]byte, 0, 16)
	hi := -1
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '-' {
			continue
		}
		var v int
		switch {
		case c >= '0' && c <= '9':
			v = int(c - '0')
		case c >= 'a' && c <= 'f':
			v = int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v = int(c-'A') + 10
		default:
			return nil, fmt.Errorf("invalid uuid char %q", c)
		}
		if hi < 0 {
			hi = v
		} else {
			out = append(out, byte(hi<<4|v))
			hi = -1
		}
	}
	if hi >= 0 || len(out) != 16 {
		return nil, fmt.Errorf("invalid uuid length")
	}
	return out, nil
}

// verifyGroupKey is the FAIL-CLOSED primitive a sender uses before encrypting to
// a group's public key. It recomputes the group-tagged leaf hash locally from
// (groupID, domain, epoch, x25519, kem), binds it to the server-supplied proof,
// and only then verifies Merkle inclusion + the Ed25519 root signature. If the
// server substitutes the group key (or returns a user leaf, a stale epoch, or a
// mismatched proof), the recomputed hash won't match and this returns false —
// the caller MUST refuse to send.
//
// Mirrors kt.ComputeGroupLeafHash + kt.VerifyGroupKey exactly.
// Args: groupID, domain, epoch, x25519B64, kemB64, proofJSON, ktSigningPubKeyB64
func verifyGroupKey(args []js.Value) (interface{}, error) {
	if len(args) < 7 {
		return nil, fmt.Errorf("verifyGroupKey requires 7 args: groupID, domain, epoch, x25519B64, kemB64, proofJSON, ktSigningPubKey")
	}
	groupID := args[0].String()
	domain := args[1].String()
	epoch := uint64(args[2].Int())
	x25519, err := unb64(args[3].String())
	if err != nil {
		return nil, fmt.Errorf("decode x25519: %w", err)
	}
	var kem []byte
	if s := args[4].String(); s != "" {
		kem, err = unb64(s)
		if err != nil {
			return nil, fmt.Errorf("decode kem: %w", err)
		}
	}
	proofJSON := args[5].String()
	ktPubKey, err := unb64(args[6].String())
	if err != nil {
		return nil, fmt.Errorf("decode ktSigningPubKey: %w", err)
	}
	if len(ktPubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid KT signing public key length: %d", len(ktPubKey))
	}

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

	// The proof's epoch must be the epoch we are verifying against — a stale
	// proof for an older epoch must not pass.
	if proof.Epoch != epoch {
		return false, nil
	}

	gid, err := uuidBytes(groupID)
	if err != nil {
		return nil, fmt.Errorf("group id: %w", err)
	}

	// Recompute the group-tagged leaf hash:
	// SHA-256("bmail-kt-group-v1:" || gid(16) || domain || epoch(8 BE) || SHA-256(x25519||kem))
	combined := make([]byte, 0, len(x25519)+len(kem))
	combined = append(combined, x25519...)
	combined = append(combined, kem...)
	pkHash := sha256.Sum256(combined)
	lh := sha256.New()
	lh.Write([]byte("bmail-kt-group-v1:"))
	lh.Write(gid)
	lh.Write([]byte(domain))
	epochBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(epochBuf, epoch)
	lh.Write(epochBuf)
	lh.Write(pkHash[:])
	expectedLeaf := lh.Sum(nil)

	serverLeaf, err := unb64(proof.LeafHash)
	if err != nil {
		return nil, fmt.Errorf("decode leaf_hash: %w", err)
	}
	// BIND: the proof must be a proof of OUR recomputed leaf, not whatever the
	// server claims. Constant-time to avoid leaking via timing.
	if subtle.ConstantTimeCompare(expectedLeaf, serverLeaf) != 1 {
		return false, nil
	}

	rootHash, err := unb64(proof.RootHash)
	if err != nil {
		return nil, fmt.Errorf("decode root_hash: %w", err)
	}
	signature, err := unb64(proof.Signature)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	siblings := make([][]byte, len(proof.Proof))
	for i, s := range proof.Proof {
		siblings[i], err = unb64(s)
		if err != nil {
			return nil, fmt.Errorf("decode proof[%d]: %w", i, err)
		}
	}

	if !verifyMerkleProof(expectedLeaf, rootHash, siblings, proof.LeafIndex, proof.TotalLeaves) {
		return false, nil
	}

	var rootMsg []byte
	rootMsg = append(rootMsg, []byte("bmail-kt-root-v1:")...)
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
