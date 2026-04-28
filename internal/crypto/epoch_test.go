package crypto

import (
	"strings"
	"testing"
)

func TestGenerateEpochKey(t *testing.T) {
	t.Parallel()
	ek, err := GenerateEpochKey(1)
	if err != nil {
		t.Fatalf("GenerateEpochKey: %v", err)
	}
	if ek.Epoch != 1 {
		t.Fatalf("expected epoch 1, got %d", ek.Epoch)
	}
	if ek.Private == nil || ek.Public == nil {
		t.Fatal("keys are nil")
	}
}

func TestEncryptDecryptEpochKey_Roundtrip(t *testing.T) {
	t.Parallel()
	// Generate two epoch keys
	epoch1, err := GenerateEpochKey(1)
	if err != nil {
		t.Fatalf("GenerateEpochKey(1): %v", err)
	}
	epoch2, err := GenerateEpochKey(2)
	if err != nil {
		t.Fatalf("GenerateEpochKey(2): %v", err)
	}

	// Encrypt epoch 1's private key under epoch 2's public key
	encrypted, err := EncryptPreviousEpochKey(epoch1.Private, 1, epoch2.Public)
	if err != nil {
		t.Fatalf("EncryptPreviousEpochKey: %v", err)
	}

	if encrypted.Epoch != 1 {
		t.Fatalf("expected epoch 1, got %d", encrypted.Epoch)
	}

	// Decrypt using epoch 2's private key
	decrypted, err := DecryptEpochKey(encrypted, epoch2.Private)
	if err != nil {
		t.Fatalf("DecryptEpochKey: %v", err)
	}

	// Verify the decrypted key matches
	if string(decrypted.Bytes()) != string(epoch1.Private.Bytes()) {
		t.Fatal("decrypted epoch key does not match original")
	}
}

func TestTraverseEpochChain(t *testing.T) {
	t.Parallel()
	// Create a chain of 5 epochs
	epochs := make([]*EpochKeyPair, 5)
	for i := 0; i < 5; i++ {
		var err error
		epochs[i], err = GenerateEpochKey(uint64(i + 1))
		if err != nil {
			t.Fatalf("GenerateEpochKey(%d): %v", i+1, err)
		}
	}

	// Encrypt each epoch's key under the next epoch's public key
	// chain[0]: epoch 4 encrypted under epoch 5
	// chain[1]: epoch 3 encrypted under epoch 4
	// chain[2]: epoch 2 encrypted under epoch 3
	// chain[3]: epoch 1 encrypted under epoch 2
	chain := make([]EncryptedEpochKey, 4)
	for i := 0; i < 4; i++ {
		prevIdx := 4 - i - 1 // 3, 2, 1, 0
		nextIdx := prevIdx + 1
		enc, err := EncryptPreviousEpochKey(epochs[prevIdx].Private, uint64(prevIdx+1), epochs[nextIdx].Public)
		if err != nil {
			t.Fatalf("EncryptPreviousEpochKey(%d -> %d): %v", prevIdx+1, nextIdx+1, err)
		}
		chain[i] = *enc
	}

	// Traverse from epoch 5's private key
	keys, err := TraverseEpochChain(chain, epochs[4].Private)
	if err != nil {
		t.Fatalf("TraverseEpochChain: %v", err)
	}

	// Verify we recovered all 4 previous epoch keys
	if len(keys) != 4 {
		t.Fatalf("expected 4 keys, got %d", len(keys))
	}

	for i := 0; i < 4; i++ {
		epoch := uint64(i + 1)
		key, ok := keys[epoch]
		if !ok {
			t.Fatalf("missing key for epoch %d", epoch)
		}
		if string(key.Bytes()) != string(epochs[i].Private.Bytes()) {
			t.Fatalf("key mismatch for epoch %d", epoch)
		}
	}
}

func TestForwardSecrecy_CannotDecryptFutureEpoch(t *testing.T) {
	t.Parallel()
	// epoch N+1 should NOT be able to decrypt epoch N+2's key
	epoch1, err := GenerateEpochKey(1)
	if err != nil {
		t.Fatalf("GenerateEpochKey(1): %v", err)
	}
	epoch2, err := GenerateEpochKey(2)
	if err != nil {
		t.Fatalf("GenerateEpochKey(2): %v", err)
	}
	epoch3, err := GenerateEpochKey(3)
	if err != nil {
		t.Fatalf("GenerateEpochKey(3): %v", err)
	}

	// Encrypt epoch 2's key under epoch 3's public key
	encrypted, err := EncryptPreviousEpochKey(epoch2.Private, 2, epoch3.Public)
	if err != nil {
		t.Fatalf("EncryptPreviousEpochKey: %v", err)
	}

	// Try to decrypt with epoch 1's key (should fail - forward secrecy)
	_, err = DecryptEpochKey(encrypted, epoch1.Private)
	if err == nil {
		t.Fatal("expected error: epoch 1 should not be able to decrypt epoch 2's key encrypted under epoch 3")
	}
}

// 3.17.3: Key rotation — encrypt messages in each epoch, rotate, then decrypt all.
func TestKeyRotation_EncryptDecryptAcrossEpochs(t *testing.T) {
	t.Parallel()
	// Generate 3 epoch key pairs.
	epochs := make([]*EpochKeyPair, 3)
	for i := 0; i < 3; i++ {
		var err error
		epochs[i], err = GenerateEpochKey(uint64(i + 1))
		if err != nil {
			t.Fatalf("GenerateEpochKey(%d): %v", i+1, err)
		}
	}

	// Encrypt a message under each epoch's public key.
	messages := []string{
		"message from epoch 1",
		"message from epoch 2",
		"message from epoch 3",
	}
	encrypted := make([]*EncryptedMessage, 3)
	for i, msg := range messages {
		var err error
		encrypted[i], err = EncryptMessage(epochs[i].Public, []byte("subject"), []byte(msg))
		if err != nil {
			t.Fatalf("EncryptMessage epoch %d: %v", i+1, err)
		}
	}

	// Build the epoch chain in traversal order (newest → oldest):
	// chain[0]: epoch 2 key encrypted under epoch 3's public key
	// chain[1]: epoch 1 key encrypted under epoch 2's public key
	chain := make([]EncryptedEpochKey, 2)
	enc2under3, err := EncryptPreviousEpochKey(epochs[1].Private, 2, epochs[2].Public)
	if err != nil {
		t.Fatalf("encrypt epoch 2 under 3: %v", err)
	}
	chain[0] = *enc2under3
	enc1under2, err := EncryptPreviousEpochKey(epochs[0].Private, 1, epochs[1].Public)
	if err != nil {
		t.Fatalf("encrypt epoch 1 under 2: %v", err)
	}
	chain[1] = *enc1under2

	// Starting from epoch 3's private key, traverse the chain to recover all keys.
	recovered, err := TraverseEpochChain(chain, epochs[2].Private)
	if err != nil {
		t.Fatalf("TraverseEpochChain: %v", err)
	}

	// Decrypt message from epoch 3 directly.
	_, dec3Body, err := DecryptMessage(epochs[2].Private, encrypted[2])
	if err != nil {
		t.Fatalf("decrypt epoch 3 message: %v", err)
	}
	if string(dec3Body) != messages[2] {
		t.Fatalf("epoch 3 body mismatch: got %q", string(dec3Body))
	}

	// Decrypt messages from older epochs using recovered keys.
	for i := 0; i < 2; i++ {
		epoch := uint64(i + 1)
		privKey, ok := recovered[epoch]
		if !ok {
			t.Fatalf("missing recovered key for epoch %d", epoch)
		}
		_, decBody, err := DecryptMessage(privKey, encrypted[i])
		if err != nil {
			t.Fatalf("decrypt epoch %d message: %v", epoch, err)
		}
		if string(decBody) != messages[i] {
			t.Fatalf("epoch %d body mismatch: got %q, want %q", epoch, string(decBody), messages[i])
		}
	}

	t.Log("key rotation: messages from all epochs decryptable via chain traversal")
}

func TestTraverseEpochChain_OutOfOrder(t *testing.T) {
	t.Parallel()
	// Create 3 epochs.
	epochs := make([]*EpochKeyPair, 3)
	for i := 0; i < 3; i++ {
		var err error
		epochs[i], err = GenerateEpochKey(uint64(i + 1))
		if err != nil {
			t.Fatalf("GenerateEpochKey(%d): %v", i+1, err)
		}
	}

	// Encrypt epoch chain links.
	enc2under3, err := EncryptPreviousEpochKey(epochs[1].Private, 2, epochs[2].Public)
	if err != nil {
		t.Fatalf("encrypt epoch 2 under 3: %v", err)
	}
	enc1under2, err := EncryptPreviousEpochKey(epochs[0].Private, 1, epochs[1].Public)
	if err != nil {
		t.Fatalf("encrypt epoch 1 under 2: %v", err)
	}

	// Build chain in WRONG order (ascending instead of descending).
	// epoch 1, epoch 2 — not monotonically decreasing.
	badChain := []EncryptedEpochKey{*enc1under2, *enc2under3}

	_, err = TraverseEpochChain(badChain, epochs[2].Private)
	if err == nil {
		t.Fatal("expected error for non-monotonically decreasing epoch chain")
	}
}

func TestTraverseEpochChain_DuplicateEpochs(t *testing.T) {
	t.Parallel()
	// Create 2 epochs.
	epoch1, err := GenerateEpochKey(1)
	if err != nil {
		t.Fatalf("GenerateEpochKey(1): %v", err)
	}
	epoch2, err := GenerateEpochKey(2)
	if err != nil {
		t.Fatalf("GenerateEpochKey(2): %v", err)
	}

	// Encrypt epoch 1's key under epoch 2.
	enc, err := EncryptPreviousEpochKey(epoch1.Private, 1, epoch2.Public)
	if err != nil {
		t.Fatalf("EncryptPreviousEpochKey: %v", err)
	}

	// Build a chain with duplicate epoch numbers: [1, 1].
	// The second entry has the same epoch as the first, violating monotonic decrease.
	dupChain := []EncryptedEpochKey{*enc, *enc}

	_, err = TraverseEpochChain(dupChain, epoch2.Private)
	if err == nil {
		t.Fatal("expected error for chain with duplicate epoch numbers")
	}
}

func TestDecryptEpochKey_WrongKey(t *testing.T) {
	t.Parallel()
	epoch1, err := GenerateEpochKey(1)
	if err != nil {
		t.Fatalf("GenerateEpochKey(1): %v", err)
	}
	epoch2, err := GenerateEpochKey(2)
	if err != nil {
		t.Fatalf("GenerateEpochKey(2): %v", err)
	}
	wrongKey, err := GenerateEpochKey(99)
	if err != nil {
		t.Fatalf("GenerateEpochKey(99): %v", err)
	}

	encrypted, err := EncryptPreviousEpochKey(epoch1.Private, 1, epoch2.Public)
	if err != nil {
		t.Fatalf("EncryptPreviousEpochKey: %v", err)
	}

	_, err = DecryptEpochKey(encrypted, wrongKey.Private)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong key")
	}
}

// Audit fix F-01/F-05: Verify epoch chain depth limit is enforced.
func TestTraverseEpochChain_MaxDepthEnforced(t *testing.T) {
	t.Parallel()
	// Build a chain that exceeds MaxEpochChainDepth.
	chain := make([]EncryptedEpochKey, MaxEpochChainDepth+1)
	for i := range chain {
		chain[i] = EncryptedEpochKey{
			Epoch:            uint64(MaxEpochChainDepth + 1 - i),
			EphemeralPubkey:  make([]byte, 32),
			EncryptedPrivKey: make([]byte, 64),
		}
	}

	dummyKey, err := GenerateEpochKey(uint64(MaxEpochChainDepth + 2))
	if err != nil {
		t.Fatalf("GenerateEpochKey: %v", err)
	}

	_, err = TraverseEpochChain(chain, dummyKey.Private)
	if err == nil {
		t.Fatal("expected error for chain exceeding MaxEpochChainDepth")
	}
	if !strings.Contains(err.Error(), "too deep") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestTraverseEpochChain_AtMaxDepthAllowed(t *testing.T) {
	t.Parallel()
	// A chain of exactly MaxEpochChainDepth should be accepted (if keys are valid).
	// We just verify it doesn't reject on length alone; it will fail on crypto
	// since we use dummy keys, but the error should NOT be "too deep".
	chain := make([]EncryptedEpochKey, MaxEpochChainDepth)
	for i := range chain {
		chain[i] = EncryptedEpochKey{
			Epoch:            uint64(MaxEpochChainDepth - i),
			EphemeralPubkey:  make([]byte, 32),
			EncryptedPrivKey: make([]byte, 64),
		}
	}

	dummyKey, err := GenerateEpochKey(uint64(MaxEpochChainDepth + 1))
	if err != nil {
		t.Fatalf("GenerateEpochKey: %v", err)
	}

	_, err = TraverseEpochChain(chain, dummyKey.Private)
	// Should fail on crypto, not on depth.
	if err != nil && strings.Contains(err.Error(), "too deep") {
		t.Fatal("chain at exactly MaxEpochChainDepth should not be rejected as too deep")
	}
}
