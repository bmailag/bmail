package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
	"time"
)

func newTestReceipt() *EnclaveReceipt {
	msgHash := sha256.Sum256([]byte("test message content"))
	ctHash := sha256.Sum256([]byte("encrypted output"))
	senderHash := HashSender("sender@example.com")
	var sigPub [32]byte
	copy(sigPub[:], []byte("test-signing-pubkey-32-bytes!xxxx"))
	return &EnclaveReceipt{
		MessageHash:      msgHash,
		CiphertextHash:   ctHash,
		SenderHash:       senderHash,
		SigningPublicKey:  sigPub,
		Timestamp:        time.Now().UTC().Truncate(time.Nanosecond),
		EnclaveID:        "mrenclave-abc123",
		TLSVerified:      true,
		SPFResult:        "pass",
		DKIMResult:       "pass",
		DMARCResult:      "pass",
		SpamScore:        0.15,
		FolderAssignment: "inbox",
	}
}

func TestSignVerifyReceipt_Roundtrip(t *testing.T) {
	t.Parallel()
	kp, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair: %v", err)
	}

	receipt := newTestReceipt()

	sig, err := SignReceipt(receipt, kp.Private)
	if err != nil {
		t.Fatalf("SignReceipt: %v", err)
	}

	if len(sig) != 64 {
		t.Fatalf("expected 64-byte signature, got %d", len(sig))
	}

	valid, err := VerifyReceipt(receipt, kp.Public)
	if err != nil {
		t.Fatalf("VerifyReceipt: %v", err)
	}
	if !valid {
		t.Fatal("signature should be valid")
	}
}

func TestVerifyReceipt_TamperedMessageHash(t *testing.T) {
	t.Parallel()
	kp, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair: %v", err)
	}

	receipt := newTestReceipt()
	_, err = SignReceipt(receipt, kp.Private)
	if err != nil {
		t.Fatalf("SignReceipt: %v", err)
	}

	// Tamper with message hash
	receipt.MessageHash[0] ^= 0xFF

	valid, err := VerifyReceipt(receipt, kp.Public)
	if err != nil {
		t.Fatalf("VerifyReceipt: %v", err)
	}
	if valid {
		t.Fatal("signature should be invalid after tampering with message hash")
	}
}

func TestVerifyReceipt_TamperedTimestamp(t *testing.T) {
	t.Parallel()
	kp, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair: %v", err)
	}

	receipt := newTestReceipt()
	_, err = SignReceipt(receipt, kp.Private)
	if err != nil {
		t.Fatalf("SignReceipt: %v", err)
	}

	receipt.Timestamp = receipt.Timestamp.Add(time.Second)

	valid, err := VerifyReceipt(receipt, kp.Public)
	if err != nil {
		t.Fatalf("VerifyReceipt: %v", err)
	}
	if valid {
		t.Fatal("signature should be invalid after tampering with timestamp")
	}
}

func TestVerifyReceipt_TamperedSpamScore(t *testing.T) {
	t.Parallel()
	kp, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair: %v", err)
	}

	receipt := newTestReceipt()
	_, err = SignReceipt(receipt, kp.Private)
	if err != nil {
		t.Fatalf("SignReceipt: %v", err)
	}

	receipt.SpamScore = 99.9

	valid, err := VerifyReceipt(receipt, kp.Public)
	if err != nil {
		t.Fatalf("VerifyReceipt: %v", err)
	}
	if valid {
		t.Fatal("signature should be invalid after tampering with spam score")
	}
}

func TestVerifyReceipt_WrongPublicKey(t *testing.T) {
	t.Parallel()
	kp1, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair: %v", err)
	}
	kp2, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair: %v", err)
	}

	receipt := newTestReceipt()
	_, err = SignReceipt(receipt, kp1.Private)
	if err != nil {
		t.Fatalf("SignReceipt: %v", err)
	}

	valid, err := VerifyReceipt(receipt, kp2.Public)
	if err != nil {
		t.Fatalf("VerifyReceipt: %v", err)
	}
	if valid {
		t.Fatal("signature should be invalid with wrong public key")
	}
}

// TestSignReceipt_CrossVerifyWithStdlib verifies that signatures produced by
// SignReceipt are standard Ed25519 and can be verified by Go's stdlib
// ed25519.Verify with no custom logic (fixes the double-hash bug).
func TestSignReceipt_CrossVerifyWithStdlib(t *testing.T) {
	t.Parallel()
	kp, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair: %v", err)
	}

	receipt := newTestReceipt()
	sig, err := SignReceipt(receipt, kp.Private)
	if err != nil {
		t.Fatalf("SignReceipt: %v", err)
	}

	// Reconstruct the signing payload independently.
	payload := receiptSigningPayload(receipt)

	// Verify with raw stdlib ed25519.Verify — no custom pre-hashing.
	pubKey := ed25519.PublicKey(kp.Public)
	if !ed25519.Verify(pubKey, payload, sig) {
		t.Fatal("signature from SignReceipt must be verifiable by raw ed25519.Verify on the payload")
	}
}

// TestSignReceipt_StdlibProducedSignatureVerifies verifies that a signature
// created with Go's stdlib ed25519.Sign is accepted by VerifyReceipt.
func TestSignReceipt_StdlibProducedSignatureVerifies(t *testing.T) {
	t.Parallel()
	kp, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair: %v", err)
	}

	receipt := newTestReceipt()
	payload := receiptSigningPayload(receipt)

	// Sign with raw stdlib.
	privKey := ed25519.PrivateKey(kp.Private)
	sig := ed25519.Sign(privKey, payload)
	receipt.Signature = sig

	// VerifyReceipt must accept it.
	valid, err := VerifyReceipt(receipt, kp.Public)
	if err != nil {
		t.Fatalf("VerifyReceipt: %v", err)
	}
	if !valid {
		t.Fatal("VerifyReceipt must accept a standard ed25519.Sign signature")
	}
}

func TestVerifyReceipt_TamperedFolder(t *testing.T) {
	t.Parallel()
	kp, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair: %v", err)
	}

	receipt := newTestReceipt()
	_, err = SignReceipt(receipt, kp.Private)
	if err != nil {
		t.Fatalf("SignReceipt: %v", err)
	}

	receipt.FolderAssignment = "spam"

	valid, err := VerifyReceipt(receipt, kp.Public)
	if err != nil {
		t.Fatalf("VerifyReceipt: %v", err)
	}
	if valid {
		t.Fatal("signature should be invalid after tampering with folder assignment")
	}
}

func TestInitSenderSecret(t *testing.T) {
	// InitSenderSecret sets a server-side secret. Calling it with different
	// values should produce different HashSender outputs for the same address.
	secret1 := make([]byte, 32)
	for i := range secret1 {
		secret1[i] = byte(i)
	}
	InitSenderSecret(secret1)

	hash1 := HashSender("test-init@example.com")

	// Verify it returns 32 bytes (SHA-256 output).
	if len(hash1) != 32 {
		t.Fatalf("expected 32-byte hash, got %d", len(hash1))
	}

	// Initialize with a different secret.
	secret2 := make([]byte, 32)
	for i := range secret2 {
		secret2[i] = byte(i + 100)
	}
	InitSenderSecret(secret2)

	hash2 := HashSender("test-init@example.com")
	if len(hash2) != 32 {
		t.Fatalf("expected 32-byte hash, got %d", len(hash2))
	}

	if hash1 == hash2 {
		t.Error("different secrets should produce different hashes for the same address")
	}
}

func TestHashSender(t *testing.T) {
	// Set a known secret for deterministic testing.
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 50)
	}
	InitSenderSecret(secret)

	addr := "deterministic@example.com"

	// Verify deterministic: same input -> same output.
	h1 := HashSender(addr)
	h2 := HashSender(addr)
	if h1 != h2 {
		t.Error("HashSender should be deterministic for the same input and secret")
	}

	// Verify different inputs give different hashes.
	h3 := HashSender("other@example.com")
	if h1 == h3 {
		t.Error("different addresses should produce different hashes")
	}

	// Verify output is 32 bytes.
	if len(h1) != 32 {
		t.Errorf("expected 32-byte hash, got %d", len(h1))
	}
}
