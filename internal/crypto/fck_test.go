package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"io"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// --- helpers ---

// genFCK returns a random 32-byte Folder Content Key.
func genFCK(t *testing.T) []byte {
	t.Helper()
	fck := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, fck); err != nil {
		t.Fatalf("generate FCK: %v", err)
	}
	return fck
}

// genMessageKey returns a random 32-byte per-file message key.
func genMessageKey(t *testing.T) []byte {
	t.Helper()
	mk := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, mk); err != nil {
		t.Fatalf("generate message key: %v", err)
	}
	return mk
}

// fckWrap wraps a 32-byte messageKey under FCK using XChaCha20-Poly1305
// with fileID as AAD.  Mirrors the fckWrapKeyJS WASM helper.
func fckWrap(fck, messageKey []byte, fileID string) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(fck)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize()) // 24 bytes
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := aead.Seal(nonce, nonce, messageKey, []byte(fileID))
	return out, nil
}

// fckUnwrap is the inverse of fckWrap.  Mirrors fckUnwrapKeyJS.
func fckUnwrap(fck, wrapped []byte, fileID string) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(fck)
	if err != nil {
		return nil, err
	}
	if len(wrapped) < aead.NonceSize()+aead.Overhead() {
		return nil, err
	}
	nonce := wrapped[:aead.NonceSize()]
	ct := wrapped[aead.NonceSize():]
	return aead.Open(nil, nonce, ct, []byte(fileID))
}

// --- tests ---

// TestFCKWrapUnwrapRoundtrip generates an X25519 keypair, wraps a random
// FCK for the pubkey using the exported DeriveWrapKey / SealWrappedKey /
// OpenWrappedKey helpers, and verifies the round-trip.
func TestFCKWrapUnwrapRoundtrip(t *testing.T) {
	t.Parallel()

	fck := genFCK(t)

	// Generate recipient X25519 keypair.
	recipientKP, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	// --- Wrap FCK for recipient ---
	ephKP, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ephemeral key: %v", err)
	}

	ss, err := ephKP.ECDH(recipientKP.Public)
	if err != nil {
		t.Fatalf("ECDH (wrap): %v", err)
	}
	ephPub := ephKP.PublicKey().Bytes()

	dk, err := DeriveWrapKey(ss, ephPub)
	if err != nil {
		t.Fatalf("DeriveWrapKey: %v", err)
	}

	encFCK, err := SealWrappedKey(dk, fck, ephPub)
	if err != nil {
		t.Fatalf("SealWrappedKey: %v", err)
	}

	// --- Unwrap FCK with recipient's private key ---
	ephPubKey, err := ecdh.X25519().NewPublicKey(ephPub)
	if err != nil {
		t.Fatalf("parse ephemeral pubkey: %v", err)
	}
	ss2, err := recipientKP.Private.ECDH(ephPubKey)
	if err != nil {
		t.Fatalf("ECDH (unwrap): %v", err)
	}

	dk2, err := DeriveWrapKey(ss2, ephPub)
	if err != nil {
		t.Fatalf("DeriveWrapKey (unwrap): %v", err)
	}

	plainFCK, err := OpenWrappedKey(dk2, encFCK, ephPub)
	if err != nil {
		t.Fatalf("OpenWrappedKey: %v", err)
	}

	if !bytes.Equal(fck, plainFCK) {
		t.Fatalf("FCK mismatch after unwrap: got %x, want %x", plainFCK, fck)
	}
}

// TestFCKFileKeyWrapUnwrapRoundtrip wraps a per-file message_key under an
// FCK with XChaCha20-Poly1305 using file_id as AAD, then unwraps and
// verifies the round-trip.
func TestFCKFileKeyWrapUnwrapRoundtrip(t *testing.T) {
	t.Parallel()

	fck := genFCK(t)
	mk := genMessageKey(t)
	fileID := "d1b2a3c4-e5f6-7890-abcd-ef1234567890"

	wrapped, err := fckWrap(fck, mk, fileID)
	if err != nil {
		t.Fatalf("fckWrap: %v", err)
	}

	// Wrapped blob should be nonce(24) + ciphertext(32) + tag(16) = 72 bytes.
	if len(wrapped) != 72 {
		t.Fatalf("expected 72-byte wrapped blob, got %d", len(wrapped))
	}

	plain, err := fckUnwrap(fck, wrapped, fileID)
	if err != nil {
		t.Fatalf("fckUnwrap: %v", err)
	}

	if !bytes.Equal(mk, plain) {
		t.Fatalf("message key mismatch: got %x, want %x", plain, mk)
	}
}

// TestFCKFileIDAADBinding wraps a message_key with file_id "A", then
// attempts to unwrap with file_id "B".  The different AAD must cause
// authentication failure, proving the file_id binding prevents wrap
// rebinding attacks.
func TestFCKFileIDAADBinding(t *testing.T) {
	t.Parallel()

	fck := genFCK(t)
	mk := genMessageKey(t)
	fileIDA := "aaaa1111-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	fileIDB := "bbbb2222-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

	wrapped, err := fckWrap(fck, mk, fileIDA)
	if err != nil {
		t.Fatalf("fckWrap: %v", err)
	}

	// Unwrap with correct file_id must succeed.
	_, err = fckUnwrap(fck, wrapped, fileIDA)
	if err != nil {
		t.Fatalf("fckUnwrap with correct file_id failed: %v", err)
	}

	// Unwrap with wrong file_id must fail.
	_, err = fckUnwrap(fck, wrapped, fileIDB)
	if err == nil {
		t.Fatal("fckUnwrap with wrong file_id should have failed but succeeded")
	}
}

// TestFCKForwardSecrecyAcrossEpochs generates two distinct FCKs (one per
// epoch).  A message_key wrapped under FCK_1 must NOT be unwrappable with
// FCK_2, proving forward secrecy across epoch boundaries.
func TestFCKForwardSecrecyAcrossEpochs(t *testing.T) {
	t.Parallel()

	fck1 := genFCK(t)
	fck2 := genFCK(t)
	mk := genMessageKey(t)
	fileID := "cc001111-cccc-cccc-cccc-cccccccccccc"

	// Wrap under FCK_1.
	wrapped, err := fckWrap(fck1, mk, fileID)
	if err != nil {
		t.Fatalf("fckWrap (fck1): %v", err)
	}

	// Unwrap with FCK_1 must succeed.
	plain, err := fckUnwrap(fck1, wrapped, fileID)
	if err != nil {
		t.Fatalf("fckUnwrap (fck1) failed: %v", err)
	}
	if !bytes.Equal(mk, plain) {
		t.Fatalf("message key mismatch with fck1")
	}

	// Unwrap with FCK_2 must fail.
	_, err = fckUnwrap(fck2, wrapped, fileID)
	if err == nil {
		t.Fatal("fckUnwrap with fck2 should have failed (forward secrecy violation)")
	}
}

// TestFCKPostCompromiseSecurity simulates member removal by testing that
// an entity holding ONLY epoch-1's FCK cannot decrypt files encrypted
// under epoch-2's FCK, and vice versa.
func TestFCKPostCompromiseSecurity(t *testing.T) {
	t.Parallel()

	fck1 := genFCK(t) // epoch 1
	fck2 := genFCK(t) // epoch 2

	mkA := genMessageKey(t) // file A, uploaded during epoch 1
	mkB := genMessageKey(t) // file B, uploaded during epoch 2

	fileIDA := "aaa00000-0000-0000-0000-000000000001"
	fileIDB := "bbb00000-0000-0000-0000-000000000002"

	// Wrap file A's key under FCK_1 (epoch 1).
	wrappedA, err := fckWrap(fck1, mkA, fileIDA)
	if err != nil {
		t.Fatalf("fckWrap file A: %v", err)
	}

	// Wrap file B's key under FCK_2 (epoch 2).
	wrappedB, err := fckWrap(fck2, mkB, fileIDB)
	if err != nil {
		t.Fatalf("fckWrap file B: %v", err)
	}

	// --- Entity with ONLY FCK_1 ---

	// Can decrypt file A.
	plainA, err := fckUnwrap(fck1, wrappedA, fileIDA)
	if err != nil {
		t.Fatalf("fck1 should unwrap file A: %v", err)
	}
	if !bytes.Equal(mkA, plainA) {
		t.Fatal("file A key mismatch")
	}

	// Cannot decrypt file B (post-compromise security).
	_, err = fckUnwrap(fck1, wrappedB, fileIDB)
	if err == nil {
		t.Fatal("fck1 should NOT unwrap file B (post-compromise security)")
	}

	// --- Entity with ONLY FCK_2 ---

	// Can decrypt file B.
	plainB, err := fckUnwrap(fck2, wrappedB, fileIDB)
	if err != nil {
		t.Fatalf("fck2 should unwrap file B: %v", err)
	}
	if !bytes.Equal(mkB, plainB) {
		t.Fatal("file B key mismatch")
	}

	// Cannot decrypt file A.
	_, err = fckUnwrap(fck2, wrappedA, fileIDA)
	if err == nil {
		t.Fatal("fck2 should NOT unwrap file A (post-compromise security)")
	}
}

// TestFCKNonceUniqueness wraps the same (FCK, file_id, message_key)
// tuple twice and verifies that the two wrapped blobs are different
// (distinct random nonces).  Both should unwrap to the same key.
func TestFCKNonceUniqueness(t *testing.T) {
	t.Parallel()

	fck := genFCK(t)
	mk := genMessageKey(t)
	fileID := "dd001111-dddd-dddd-dddd-dddddddddddd"

	wrapped1, err := fckWrap(fck, mk, fileID)
	if err != nil {
		t.Fatalf("fckWrap #1: %v", err)
	}
	wrapped2, err := fckWrap(fck, mk, fileID)
	if err != nil {
		t.Fatalf("fckWrap #2: %v", err)
	}

	// The two blobs must differ (random nonces).
	if bytes.Equal(wrapped1, wrapped2) {
		t.Fatal("two wraps of the same input produced identical blobs — nonce reuse")
	}

	// Both must unwrap to the same message_key.
	plain1, err := fckUnwrap(fck, wrapped1, fileID)
	if err != nil {
		t.Fatalf("fckUnwrap #1: %v", err)
	}
	plain2, err := fckUnwrap(fck, wrapped2, fileID)
	if err != nil {
		t.Fatalf("fckUnwrap #2: %v", err)
	}

	if !bytes.Equal(plain1, plain2) {
		t.Fatalf("unwrapped keys differ: %x vs %x", plain1, plain2)
	}
	if !bytes.Equal(mk, plain1) {
		t.Fatalf("unwrapped key doesn't match original: got %x, want %x", plain1, mk)
	}
}
