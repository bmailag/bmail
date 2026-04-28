package crypto

import (
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestEncryptDecryptMessage_Roundtrip(t *testing.T) {
	t.Parallel()
	// Generate recipient key pair
	kp, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	subject := []byte("Top Secret Subject")
	body := []byte("This is a highly confidential message body with some content.")

	// Encrypt
	encrypted, err := EncryptMessage(kp.Public, subject, body)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}

	// Verify encrypted message has all fields
	if len(encrypted.EphemeralPubkey) != 32 {
		t.Fatalf("expected 32-byte ephemeral pubkey, got %d", len(encrypted.EphemeralPubkey))
	}
	if len(encrypted.EncryptedMessageKey) == 0 {
		t.Fatal("encrypted message key is empty")
	}
	if len(encrypted.EncryptedBody) == 0 {
		t.Fatal("encrypted body is empty")
	}
	if len(encrypted.EncryptedSubject) == 0 {
		t.Fatal("encrypted subject is empty")
	}

	// Decrypt
	decSubject, decBody, err := DecryptMessage(kp.Private, encrypted)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}

	if !bytes.Equal(subject, decSubject) {
		t.Fatalf("subject mismatch: got %q, want %q", decSubject, subject)
	}
	if !bytes.Equal(body, decBody) {
		t.Fatalf("body mismatch: got %q, want %q", decBody, body)
	}
}

func TestEncryptMessage_EmptyContent(t *testing.T) {
	t.Parallel()
	kp, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	encrypted, err := EncryptMessage(kp.Public, []byte(""), []byte(""))
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}

	decSubject, decBody, err := DecryptMessage(kp.Private, encrypted)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}

	if len(decSubject) != 0 {
		t.Fatalf("expected empty subject, got %q", decSubject)
	}
	if len(decBody) != 0 {
		t.Fatalf("expected empty body, got %q", decBody)
	}
}

func TestDecryptMessage_WrongKey(t *testing.T) {
	t.Parallel()
	sender, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	wrongRecipient, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	encrypted, err := EncryptMessage(sender.Public, []byte("subject"), []byte("body"))
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}

	// Try decrypting with wrong key
	_, _, err = DecryptMessage(wrongRecipient.Private, encrypted)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong key")
	}
}

func TestDecryptMessage_TamperedCiphertext(t *testing.T) {
	t.Parallel()
	kp, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	encrypted, err := EncryptMessage(kp.Public, []byte("subject"), []byte("body"))
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}

	// Tamper with encrypted body
	if len(encrypted.EncryptedBody) > 25 {
		encrypted.EncryptedBody[25] ^= 0xFF
	}

	_, _, err = DecryptMessage(kp.Private, encrypted)
	if err == nil {
		t.Fatal("expected error when decrypting tampered ciphertext")
	}
}

func TestDecryptMessage_TamperedMessageKey(t *testing.T) {
	t.Parallel()
	kp, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	encrypted, err := EncryptMessage(kp.Public, []byte("subject"), []byte("body"))
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}

	// Tamper with encrypted message key
	if len(encrypted.EncryptedMessageKey) > 25 {
		encrypted.EncryptedMessageKey[25] ^= 0xFF
	}

	_, _, err = DecryptMessage(kp.Private, encrypted)
	if err == nil {
		t.Fatal("expected error when decrypting with tampered message key")
	}
}

func TestDecryptMessage_TamperedEphemeralKey(t *testing.T) {
	t.Parallel()
	kp, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	encrypted, err := EncryptMessage(kp.Public, []byte("subject"), []byte("body"))
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}

	// Replace ephemeral key with random bytes
	if _, err := rand.Read(encrypted.EphemeralPubkey); err != nil {
		t.Fatalf("generate random bytes: %v", err)
	}

	_, _, err = DecryptMessage(kp.Private, encrypted)
	if err == nil {
		t.Fatal("expected error when decrypting with tampered ephemeral key")
	}
}

func TestDecryptMessage_InvalidEphemeralKeyLength(t *testing.T) {
	t.Parallel()
	kp, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	encrypted, err := EncryptMessage(kp.Public, []byte("subject"), []byte("body"))
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}

	tests := []struct {
		name    string
		keyLen  int
	}{
		{"31-byte ephemeral key", 31},
		{"33-byte ephemeral key", 33},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			msg := &EncryptedMessage{
				EphemeralPubkey:     make([]byte, tc.keyLen),
				EncryptedMessageKey: encrypted.EncryptedMessageKey,
				EncryptedBody:       encrypted.EncryptedBody,
				EncryptedSubject:    encrypted.EncryptedSubject,
			}
			_, _, err := DecryptMessage(kp.Private, msg)
			if err == nil {
				t.Fatalf("expected error for %d-byte ephemeral key, got nil", tc.keyLen)
			}
			expected := fmt.Sprintf("invalid ephemeral public key length: %d (expected 32)", tc.keyLen)
			if err.Error() != expected {
				t.Fatalf("unexpected error message:\n got: %s\nwant: %s", err.Error(), expected)
			}
		})
	}
}

func TestZeroBytes(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	rand.Read(key)

	// Verify key is non-zero before.
	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("key should not be all zeros before ZeroBytes")
	}

	ZeroBytes(key)

	for i, b := range key {
		if b != 0 {
			t.Fatalf("byte %d is %d, expected 0 after ZeroBytes", i, b)
		}
	}
}

func TestKeyZeroization_DeriveKey(t *testing.T) {
	t.Parallel()
	// Test that deriveKey produces a key that can be zeroed.
	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)

	derived, err := deriveKey(sharedSecret, []byte("test-salt"), "test-info")
	if err != nil {
		t.Fatalf("deriveKey: %v", err)
	}
	if len(derived) != 32 {
		t.Fatalf("expected 32-byte derived key, got %d", len(derived))
	}

	// Verify it's non-zero.
	allZero := true
	for _, b := range derived {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("derived key should not be all zeros")
	}

	// Zero it and verify.
	ZeroBytes(derived)
	for i, b := range derived {
		if b != 0 {
			t.Fatalf("byte %d is %d, expected 0 after ZeroBytes", i, b)
		}
	}
}

func TestNonceUniqueness(t *testing.T) {
	t.Parallel()
	const count = 10000
	seen := make(map[string]struct{}, count)
	for i := 0; i < count; i++ {
		nonce, err := secureNonce(24)
		if err != nil {
			t.Fatalf("secureNonce[%d]: %v", i, err)
		}
		key := string(nonce)
		if _, dup := seen[key]; dup {
			t.Fatalf("duplicate nonce at iteration %d", i)
		}
		seen[key] = struct{}{}
	}
}

func TestRewrapMessageKey_Roundtrip(t *testing.T) {
	t.Parallel()
	// Sender encrypts a message for themselves (simulating attachment upload).
	sender, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair (sender): %v", err)
	}
	recipient, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair (recipient): %v", err)
	}

	// Encrypt attachment: metadata as subject, data as body.
	metadata := []byte(`{"filename":"test.pdf","content_type":"application/pdf"}`)
	data := []byte("fake attachment data here")
	encrypted, err := EncryptMessage(sender.Public, metadata, data)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}

	// Sender can decrypt.
	decMeta, decData, err := DecryptMessage(sender.Private, encrypted)
	if err != nil {
		t.Fatalf("DecryptMessage (sender): %v", err)
	}
	if !bytes.Equal(metadata, decMeta) || !bytes.Equal(data, decData) {
		t.Fatal("sender decryption mismatch")
	}

	// Rewrap for recipient.
	newEphPub, newEncKey, err := RewrapMessageKey(
		encrypted.EphemeralPubkey, encrypted.EncryptedMessageKey,
		sender.Private, recipient.Public,
	)
	if err != nil {
		t.Fatalf("RewrapMessageKey: %v", err)
	}
	if len(newEphPub) != 32 {
		t.Fatalf("expected 32-byte new ephemeral pubkey, got %d", len(newEphPub))
	}

	// Recipient decrypts using the rewrapped key + original encrypted body/subject.
	rewrapped := &EncryptedMessage{
		EphemeralPubkey:     newEphPub,
		EncryptedMessageKey: newEncKey,
		EncryptedBody:       encrypted.EncryptedBody,
		EncryptedSubject:    encrypted.EncryptedSubject,
	}
	decMeta2, decData2, err := DecryptMessage(recipient.Private, rewrapped)
	if err != nil {
		t.Fatalf("DecryptMessage (recipient after rewrap): %v", err)
	}
	if !bytes.Equal(metadata, decMeta2) {
		t.Fatalf("metadata mismatch after rewrap: got %q, want %q", decMeta2, metadata)
	}
	if !bytes.Equal(data, decData2) {
		t.Fatalf("data mismatch after rewrap: got %q, want %q", decData2, data)
	}
}

func TestRewrapMessageKey_WrongSenderKey(t *testing.T) {
	t.Parallel()
	sender, _ := GenerateX25519KeyPair()
	wrongSender, _ := GenerateX25519KeyPair()
	recipient, _ := GenerateX25519KeyPair()

	encrypted, err := EncryptMessage(sender.Public, []byte("meta"), []byte("data"))
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}

	// Rewrap with wrong sender key — should fail to unwrap.
	_, _, err = RewrapMessageKey(
		encrypted.EphemeralPubkey, encrypted.EncryptedMessageKey,
		wrongSender.Private, recipient.Public,
	)
	if err == nil {
		t.Fatal("expected error when rewrapping with wrong sender key")
	}
}

func TestRewrapMessageKey_InvalidEphemeralKey(t *testing.T) {
	t.Parallel()
	sender, _ := GenerateX25519KeyPair()
	recipient, _ := GenerateX25519KeyPair()

	_, _, err := RewrapMessageKey(
		make([]byte, 31), // wrong length
		make([]byte, 100),
		sender.Private, recipient.Public,
	)
	if err == nil {
		t.Fatal("expected error for invalid ephemeral key length")
	}
}

func TestEncryptMessage_LargeBody(t *testing.T) {
	t.Parallel()
	kp, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	// 1 MB body
	body := make([]byte, 1<<20)
	if _, err := rand.Read(body); err != nil {
		t.Fatalf("generate random body: %v", err)
	}
	subject := []byte("Large message test")

	encrypted, err := EncryptMessage(kp.Public, subject, body)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}

	decSubject, decBody, err := DecryptMessage(kp.Private, encrypted)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}

	if !bytes.Equal(subject, decSubject) {
		t.Fatal("subject mismatch")
	}
	if !bytes.Equal(body, decBody) {
		t.Fatal("body mismatch")
	}
}

// TestEncryptMessageWithHeaders_Roundtrip exercises the Phase B3
// envelope shape: subject + body + headers slot under one message key.
// The client should be able to unwrap the key once and decrypt headers
// independently of body via DecryptHeaders.
func TestEncryptMessageWithHeaders_Roundtrip(t *testing.T) {
	t.Parallel()
	kp, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	subject := []byte("Quarterly Report")
	body := []byte("All metrics are up.")
	headers := []byte(`{"Headers":{"From":["Alice Smith <alice@example.com>"],"To":["bob@bmail.ag"],"Date":["Tue, 7 Apr 2026 12:00:00 +0000"]}}`)

	enc, err := EncryptMessageWithHeaders(kp.Public, subject, body, headers)
	if err != nil {
		t.Fatalf("EncryptMessageWithHeaders: %v", err)
	}
	if len(enc.EncryptedHeaders) == 0 {
		t.Fatal("encrypted headers slot is empty")
	}

	// Body + subject still round-trip via the existing DecryptMessage path.
	decSubject, decBody, err := DecryptMessage(kp.Private, enc)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	if !bytes.Equal(subject, decSubject) {
		t.Errorf("subject mismatch: got %q want %q", decSubject, subject)
	}
	if !bytes.Equal(body, decBody) {
		t.Errorf("body mismatch: got %q want %q", decBody, body)
	}

	// Headers decrypt independently with just the envelope keys + the
	// headers ciphertext.
	decHeaders, err := DecryptHeaders(kp.Private, enc.EphemeralPubkey, enc.EncryptedMessageKey, enc.EncryptedHeaders)
	if err != nil {
		t.Fatalf("DecryptHeaders: %v", err)
	}
	if !bytes.Equal(headers, decHeaders) {
		t.Errorf("headers mismatch:\n got %s\nwant %s", decHeaders, headers)
	}
}

// TestDecryptHeaders_WrongAAD verifies the headers slot's AAD binding
// — feeding the headers ciphertext to the subject AAD opener (or vice
// versa) must fail authentication.
func TestDecryptHeaders_WrongAAD(t *testing.T) {
	t.Parallel()
	kp, _ := GenerateX25519KeyPair()
	enc, _ := EncryptMessageWithHeaders(kp.Public, []byte("subj"), []byte("body"), []byte(`{"Headers":{}}`))

	// Try to decrypt headers as subject — should fail.
	if _, err := DecryptSubjectOnly(kp.Private, enc.EphemeralPubkey, enc.EncryptedMessageKey, enc.EncryptedHeaders); err == nil {
		t.Error("expected DecryptSubjectOnly to reject headers ciphertext (wrong AAD)")
	}
}

// TestEncryptMessageWithHeaders_NilHeaders falls back to the legacy
// two-slot encoding when no headers are provided.
func TestEncryptMessageWithHeaders_NilHeaders(t *testing.T) {
	t.Parallel()
	kp, _ := GenerateX25519KeyPair()
	enc, err := EncryptMessageWithHeaders(kp.Public, []byte("subj"), []byte("body"), nil)
	if err != nil {
		t.Fatalf("EncryptMessageWithHeaders: %v", err)
	}
	if len(enc.EncryptedHeaders) != 0 {
		t.Errorf("expected empty headers slot when input is nil, got %d bytes", len(enc.EncryptedHeaders))
	}
	// Subject + body still round-trip.
	if _, _, err := DecryptMessage(kp.Private, enc); err != nil {
		t.Errorf("DecryptMessage: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Hybrid X25519 + ML-KEM-768 tests
// ---------------------------------------------------------------------------

func generateKEMDK(t *testing.T) *mlkem.DecapsulationKey768 {
	t.Helper()
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	return dk
}

func TestEncryptMessageHybrid_Roundtrip(t *testing.T) {
	t.Parallel()
	kp, _ := GenerateX25519KeyPair()
	kemDK := generateKEMDK(t)
	kemEK := kemDK.EncapsulationKey()

	subject := []byte("PQ Subject")
	body := []byte("Post-quantum encrypted body content.")

	enc, err := EncryptMessageHybrid(kp.Public, kemEK, subject, body)
	if err != nil {
		t.Fatalf("EncryptMessageHybrid: %v", err)
	}

	if len(enc.EphemeralPubkey) != HybridEnvelopeKeySize {
		t.Fatalf("expected hybrid envelope key size %d, got %d", HybridEnvelopeKeySize, len(enc.EphemeralPubkey))
	}
	if enc.EphemeralPubkey[0] != EnvelopeVersionHybrid {
		t.Fatalf("expected version byte 0x%02x, got 0x%02x", EnvelopeVersionHybrid, enc.EphemeralPubkey[0])
	}

	decSubject, decBody, err := DecryptMessageAuto(kp.Private, kemDK, enc)
	if err != nil {
		t.Fatalf("DecryptMessageAuto: %v", err)
	}
	if !bytes.Equal(subject, decSubject) {
		t.Errorf("subject mismatch")
	}
	if !bytes.Equal(body, decBody) {
		t.Errorf("body mismatch")
	}
}

func TestEncryptMessageHybrid_ClassicalFallback(t *testing.T) {
	t.Parallel()
	kp, _ := GenerateX25519KeyPair()

	subject := []byte("Classical Subject")
	body := []byte("Classical body.")

	// nil KEM EK → classical envelope
	enc, err := EncryptMessageHybrid(kp.Public, nil, subject, body)
	if err != nil {
		t.Fatalf("EncryptMessageHybrid (nil KEM): %v", err)
	}

	if len(enc.EphemeralPubkey) != 32 {
		t.Fatalf("expected classical 32-byte ephemeral pubkey, got %d", len(enc.EphemeralPubkey))
	}

	// DecryptMessageAuto with nil KEM DK should work
	decSubject, decBody, err := DecryptMessageAuto(kp.Private, nil, enc)
	if err != nil {
		t.Fatalf("DecryptMessageAuto (classical): %v", err)
	}
	if !bytes.Equal(subject, decSubject) || !bytes.Equal(body, decBody) {
		t.Errorf("content mismatch in classical fallback")
	}
}

func TestDecryptMessageAuto_ClassicalMessage(t *testing.T) {
	t.Parallel()
	kp, _ := GenerateX25519KeyPair()
	kemDK := generateKEMDK(t)

	// Encrypt with old classical EncryptMessage
	enc, err := EncryptMessage(kp.Public, []byte("old subject"), []byte("old body"))
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}

	// DecryptMessageAuto should handle 32-byte envelope key (backward compat)
	subject, body, err := DecryptMessageAuto(kp.Private, kemDK, enc)
	if err != nil {
		t.Fatalf("DecryptMessageAuto on classical message: %v", err)
	}
	if !bytes.Equal(subject, []byte("old subject")) || !bytes.Equal(body, []byte("old body")) {
		t.Errorf("content mismatch decrypting classical message with Auto")
	}
}

func TestEncryptMessageWithHeadersHybrid_Roundtrip(t *testing.T) {
	t.Parallel()
	kp, _ := GenerateX25519KeyPair()
	kemDK := generateKEMDK(t)
	kemEK := kemDK.EncapsulationKey()

	subject := []byte("PQ Subj")
	body := []byte("PQ Body")
	headers := []byte(`{"From":["alice@bmail.ag"]}`)

	enc, err := EncryptMessageWithHeadersHybrid(kp.Public, kemEK, subject, body, headers)
	if err != nil {
		t.Fatalf("EncryptMessageWithHeadersHybrid: %v", err)
	}

	// Decrypt message
	decSubject, decBody, err := DecryptMessageAuto(kp.Private, kemDK, enc)
	if err != nil {
		t.Fatalf("DecryptMessageAuto: %v", err)
	}
	if !bytes.Equal(subject, decSubject) || !bytes.Equal(body, decBody) {
		t.Errorf("content mismatch")
	}

	// Decrypt headers
	decHeaders, err := DecryptHeadersAuto(kp.Private, kemDK, enc.EphemeralPubkey, enc.EncryptedMessageKey, enc.EncryptedHeaders)
	if err != nil {
		t.Fatalf("DecryptHeadersAuto: %v", err)
	}
	if !bytes.Equal(headers, decHeaders) {
		t.Errorf("headers mismatch")
	}
}

func TestRewrapMessageKeyHybrid_ClassicalToHybrid(t *testing.T) {
	t.Parallel()
	sender, _ := GenerateX25519KeyPair()
	recipient, _ := GenerateX25519KeyPair()
	recipientKEMDK := generateKEMDK(t)
	recipientKEMEK := recipientKEMDK.EncapsulationKey()

	// Original: classical envelope for sender
	enc, err := EncryptMessage(sender.Public, []byte("meta"), []byte("data"))
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}

	// Rewrap: classical original → hybrid for recipient
	newEnvKey, newEncMK, err := RewrapMessageKeyHybrid(
		enc.EphemeralPubkey, enc.EncryptedMessageKey,
		sender.Private, nil,
		recipient.Public, recipientKEMEK,
	)
	if err != nil {
		t.Fatalf("RewrapMessageKeyHybrid: %v", err)
	}

	if len(newEnvKey) != HybridEnvelopeKeySize {
		t.Fatalf("expected hybrid envelope key, got %d bytes", len(newEnvKey))
	}

	// Recipient decrypts the rewrapped key
	messageKey, err := unwrapEnvelope(recipient.Private, recipientKEMDK, newEnvKey, newEncMK)
	if err != nil {
		t.Fatalf("unwrapEnvelope after rewrap: %v", err)
	}
	defer ZeroBytes(messageKey)

	// Use the message key to decrypt the original body
	decBody, err := openXChaCha20(messageKey, enc.EncryptedBody, []byte("body"))
	if err != nil {
		t.Fatalf("decrypt body with rewrapped key: %v", err)
	}
	if !bytes.Equal(decBody, []byte("data")) {
		t.Errorf("body mismatch after rewrap")
	}
}

func TestRewrapMessageKeyHybrid_HybridToClassical(t *testing.T) {
	t.Parallel()
	sender, _ := GenerateX25519KeyPair()
	senderKEMDK := generateKEMDK(t)
	senderKEMEK := senderKEMDK.EncapsulationKey()
	recipient, _ := GenerateX25519KeyPair()

	// Original: hybrid envelope for sender
	enc, err := EncryptMessageHybrid(sender.Public, senderKEMEK, []byte("meta"), []byte("data"))
	if err != nil {
		t.Fatalf("EncryptMessageHybrid: %v", err)
	}

	// Rewrap: hybrid original → classical for recipient (no KEM)
	newEnvKey, newEncMK, err := RewrapMessageKeyHybrid(
		enc.EphemeralPubkey, enc.EncryptedMessageKey,
		sender.Private, senderKEMDK,
		recipient.Public, nil,
	)
	if err != nil {
		t.Fatalf("RewrapMessageKeyHybrid: %v", err)
	}

	if len(newEnvKey) != 32 {
		t.Fatalf("expected classical envelope key (32 bytes), got %d", len(newEnvKey))
	}

	// Recipient decrypts
	messageKey, err := unwrapEnvelope(recipient.Private, nil, newEnvKey, newEncMK)
	if err != nil {
		t.Fatalf("unwrapEnvelope after rewrap: %v", err)
	}
	defer ZeroBytes(messageKey)

	decBody, err := openXChaCha20(messageKey, enc.EncryptedBody, []byte("body"))
	if err != nil {
		t.Fatalf("decrypt body: %v", err)
	}
	if !bytes.Equal(decBody, []byte("data")) {
		t.Errorf("body mismatch")
	}
}
