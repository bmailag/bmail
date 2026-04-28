package crypto

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
)

// Tests mirroring the crypto operations that the WASM module (web/wasm/main.go)
// exposes to the frontend. Since syscall/js only compiles under GOOS=js GOARCH=wasm,
// we test the underlying Go functions directly.

// ── 1. Key Generation (X25519 keypair) ──────────────────────

func TestWASM_GenerateX25519KeyPair(t *testing.T) {
	t.Parallel()
	kp, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	if kp.Private == nil {
		t.Fatal("private key is nil")
	}
	if kp.Public == nil {
		t.Fatal("public key is nil")
	}
	if len(kp.Public.Bytes()) != 32 {
		t.Fatalf("expected 32-byte public key, got %d", len(kp.Public.Bytes()))
	}
	if len(kp.Private.Bytes()) != 32 {
		t.Fatalf("expected 32-byte private key, got %d", len(kp.Private.Bytes()))
	}

	// Two generated keypairs must differ.
	kp2, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair (2nd): %v", err)
	}
	if bytes.Equal(kp.Private.Bytes(), kp2.Private.Bytes()) {
		t.Fatal("two generated private keys must not be identical")
	}
}

func TestWASM_GenerateEd25519KeyPair(t *testing.T) {
	t.Parallel()
	kp, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair: %v", err)
	}
	if len(kp.Public) != ed25519.PublicKeySize {
		t.Fatalf("expected %d-byte public key, got %d", ed25519.PublicKeySize, len(kp.Public))
	}
	if len(kp.Private) != ed25519.PrivateKeySize {
		t.Fatalf("expected %d-byte private key, got %d", ed25519.PrivateKeySize, len(kp.Private))
	}
}

// ── 2. Encrypt/Decrypt Message Roundtrip ────────────────────

func TestWASM_EncryptDecryptMessage_Roundtrip(t *testing.T) {
	t.Parallel()
	kp, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	subject := []byte("Encrypted subject line")
	body := []byte("This is the confidential message body for WASM roundtrip testing.")

	encrypted, err := EncryptMessage(kp.Public, subject, body)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}

	// Verify ciphertext differs from plaintext.
	if bytes.Equal(encrypted.EncryptedBody[24:], body) {
		t.Fatal("encrypted body should not equal plaintext")
	}

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

func TestWASM_EncryptDecryptMessage_EmptySubjectAndBody(t *testing.T) {
	t.Parallel()
	kp, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	encrypted, err := EncryptMessage(kp.Public, []byte{}, []byte{})
	if err != nil {
		t.Fatalf("EncryptMessage with empty content: %v", err)
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

func TestWASM_EncryptDecryptMessage_WrongKeyFails(t *testing.T) {
	t.Parallel()
	kp1, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	kp2, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair (2nd): %v", err)
	}

	encrypted, err := EncryptMessage(kp1.Public, []byte("subject"), []byte("body"))
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}

	_, _, err = DecryptMessage(kp2.Private, encrypted)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong private key")
	}
}

// ── 3. Sign/Verify Roundtrip (Ed25519) ─────────────────────

func TestWASM_SignVerify_Roundtrip(t *testing.T) {
	t.Parallel()
	kp, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair: %v", err)
	}

	message := []byte("Message to be signed for WASM roundtrip test")
	sig := ed25519.Sign(kp.Private, message)

	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("expected %d-byte signature, got %d", ed25519.SignatureSize, len(sig))
	}

	if !ed25519.Verify(kp.Public, message, sig) {
		t.Fatal("valid signature failed verification")
	}
}

func TestWASM_SignVerify_WrongKeyFails(t *testing.T) {
	t.Parallel()
	kp1, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair: %v", err)
	}
	kp2, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair (2nd): %v", err)
	}

	message := []byte("Signed with kp1")
	sig := ed25519.Sign(kp1.Private, message)

	if ed25519.Verify(kp2.Public, message, sig) {
		t.Fatal("signature should not verify with a different public key")
	}
}

func TestWASM_SignVerify_TamperedMessageFails(t *testing.T) {
	t.Parallel()
	kp, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair: %v", err)
	}

	message := []byte("Original message")
	sig := ed25519.Sign(kp.Private, message)

	tampered := []byte("Tampered message")
	if ed25519.Verify(kp.Public, tampered, sig) {
		t.Fatal("signature should not verify with tampered message")
	}
}

// ── 4. Recovery Mnemonic Generation + Key Derivation ────────

func TestWASM_GenerateMnemonic(t *testing.T) {
	t.Parallel()
	mnemonic, err := GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic: %v", err)
	}

	words := strings.Fields(mnemonic)
	if len(words) != 24 {
		t.Fatalf("expected 24-word mnemonic, got %d words: %q", len(words), mnemonic)
	}

	// Two mnemonics must differ.
	mnemonic2, err := GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic (2nd): %v", err)
	}
	if mnemonic == mnemonic2 {
		t.Fatal("two generated mnemonics must not be identical")
	}
}

func TestWASM_DeriveRecoveryKey(t *testing.T) {
	t.Parallel()
	mnemonic, err := GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic: %v", err)
	}

	key, err := DeriveRecoveryKey(mnemonic)
	if err != nil {
		t.Fatalf("DeriveRecoveryKey: %v", err)
	}

	// Key must not be all zeros.
	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("recovery key must not be all zeros")
	}

	// Same mnemonic must derive the same key (deterministic).
	key2, err := DeriveRecoveryKey(mnemonic)
	if err != nil {
		t.Fatalf("DeriveRecoveryKey (2nd): %v", err)
	}
	if key != key2 {
		t.Fatal("same mnemonic must derive the same recovery key")
	}
}

func TestWASM_DeriveRecoveryKey_DifferentMnemonics(t *testing.T) {
	t.Parallel()
	m1, err := GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic: %v", err)
	}
	m2, err := GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic (2nd): %v", err)
	}

	k1, err := DeriveRecoveryKey(m1)
	if err != nil {
		t.Fatalf("DeriveRecoveryKey: %v", err)
	}
	k2, err := DeriveRecoveryKey(m2)
	if err != nil {
		t.Fatalf("DeriveRecoveryKey (2nd): %v", err)
	}

	if k1 == k2 {
		t.Fatal("different mnemonics must derive different recovery keys")
	}
}

func TestWASM_DeriveRecoveryKey_InvalidMnemonic(t *testing.T) {
	t.Parallel()
	_, err := DeriveRecoveryKey("invalid mnemonic phrase that is not valid bip39")
	if err == nil {
		t.Fatal("expected error for invalid mnemonic")
	}
}

// ── 5. Encrypt/Decrypt with Recovery Key Roundtrip ──────────

func TestWASM_EncryptDecryptWithRecoveryKey_Roundtrip(t *testing.T) {
	t.Parallel()
	mnemonic, err := GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic: %v", err)
	}

	recoveryKey, err := DeriveRecoveryKey(mnemonic)
	if err != nil {
		t.Fatalf("DeriveRecoveryKey: %v", err)
	}

	// Simulate encrypting a private key bundle (as the WASM module does).
	privateKeyData := []byte(`{"encryption":"base64enckey","signing":"base64sigkey"}`)

	encrypted, err := EncryptWithRecoveryKey(privateKeyData, recoveryKey)
	if err != nil {
		t.Fatalf("EncryptWithRecoveryKey: %v", err)
	}

	if len(encrypted) == 0 {
		t.Fatal("encrypted data is empty")
	}

	// Ciphertext must differ from plaintext.
	if bytes.Contains(encrypted, privateKeyData) {
		t.Fatal("encrypted data should not contain plaintext")
	}

	decrypted, err := DecryptWithRecoveryKey(encrypted, recoveryKey)
	if err != nil {
		t.Fatalf("DecryptWithRecoveryKey: %v", err)
	}

	if !bytes.Equal(privateKeyData, decrypted) {
		t.Fatalf("decrypted data mismatch: got %q, want %q", decrypted, privateKeyData)
	}
}

func TestWASM_DecryptWithRecoveryKey_WrongKeyFails(t *testing.T) {
	t.Parallel()
	m1, err := GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic: %v", err)
	}
	m2, err := GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic (2nd): %v", err)
	}

	k1, err := DeriveRecoveryKey(m1)
	if err != nil {
		t.Fatalf("DeriveRecoveryKey: %v", err)
	}
	k2, err := DeriveRecoveryKey(m2)
	if err != nil {
		t.Fatalf("DeriveRecoveryKey (2nd): %v", err)
	}

	plaintext := []byte("secret private key material")
	encrypted, err := EncryptWithRecoveryKey(plaintext, k1)
	if err != nil {
		t.Fatalf("EncryptWithRecoveryKey: %v", err)
	}

	_, err = DecryptWithRecoveryKey(encrypted, k2)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong recovery key")
	}
}

func TestWASM_EncryptDecryptPrivateKey_WithExportKey(t *testing.T) {
	t.Parallel()
	// Simulate the WASM flow: encrypt a private key with an OPAQUE-derived export key,
	// then decrypt it.
	exportKey := make([]byte, 32)
	for i := range exportKey {
		exportKey[i] = byte(i + 1) // non-zero deterministic key for testing
	}

	kp, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	privKeyBytes := kp.Private.Bytes()

	encrypted, err := EncryptPrivateKey(privKeyBytes, exportKey, AADPrivateKey)
	if err != nil {
		t.Fatalf("EncryptPrivateKey: %v", err)
	}

	decrypted, err := DecryptPrivateKey(encrypted, exportKey, AADPrivateKey)
	if err != nil {
		t.Fatalf("DecryptPrivateKey: %v", err)
	}

	if !bytes.Equal(privKeyBytes, decrypted) {
		t.Fatal("decrypted private key does not match original")
	}
}

func TestWASM_EncryptPrivateKey_WrongAADFails(t *testing.T) {
	t.Parallel()
	exportKey := make([]byte, 32)
	for i := range exportKey {
		exportKey[i] = byte(i + 1)
	}

	plaintext := []byte("private key bytes here")
	encrypted, err := EncryptPrivateKey(plaintext, exportKey, AADPrivateKey)
	if err != nil {
		t.Fatalf("EncryptPrivateKey: %v", err)
	}

	// Decrypt with wrong AAD must fail (AAD binding).
	_, err = DecryptPrivateKey(encrypted, exportKey, AADRecoveryKey)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong AAD")
	}
}

// ── Full WASM Registration Flow Simulation ──────────────────

func TestWASM_FullRegistrationFlow(t *testing.T) {
	t.Parallel()
	// Simulates the complete opaqueRegistrationFinish flow from the WASM module:
	// generate keys, encrypt private keys with export key, generate mnemonic,
	// derive recovery key, encrypt private keys with recovery key, then verify
	// everything can be decrypted.

	// Step 1: Generate keypairs.
	encKP, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	sigKP, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair: %v", err)
	}

	// Step 2: Simulate export key (normally derived from OPAQUE).
	exportKey := make([]byte, 32)
	for i := range exportKey {
		exportKey[i] = byte(i + 42)
	}

	// Step 3: Encrypt private keys with export key.
	allPrivKeys := append(encKP.Private.Bytes(), sigKP.Private...)
	encryptedPrivKey, err := EncryptPrivateKey(allPrivKeys, exportKey, AADPrivateKey)
	if err != nil {
		t.Fatalf("EncryptPrivateKey: %v", err)
	}

	// Step 4: Generate mnemonic and derive recovery key.
	mnemonic, err := GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic: %v", err)
	}
	recoveryKey, err := DeriveRecoveryKey(mnemonic)
	if err != nil {
		t.Fatalf("DeriveRecoveryKey: %v", err)
	}

	// Step 5: Encrypt private keys with recovery key.
	encryptedRecovery, err := EncryptWithRecoveryKey(allPrivKeys, recoveryKey)
	if err != nil {
		t.Fatalf("EncryptWithRecoveryKey: %v", err)
	}

	// Verify: decrypt with export key.
	decryptedExport, err := DecryptPrivateKey(encryptedPrivKey, exportKey, AADPrivateKey)
	if err != nil {
		t.Fatalf("DecryptPrivateKey (export key): %v", err)
	}
	if !bytes.Equal(allPrivKeys, decryptedExport) {
		t.Fatal("export-key decryption mismatch")
	}

	// Verify: decrypt with recovery key.
	decryptedRecovery, err := DecryptWithRecoveryKey(encryptedRecovery, recoveryKey)
	if err != nil {
		t.Fatalf("DecryptWithRecoveryKey: %v", err)
	}
	if !bytes.Equal(allPrivKeys, decryptedRecovery) {
		t.Fatal("recovery-key decryption mismatch")
	}

	// Verify: signing still works with the recovered key.
	recoveredSigningKey := ed25519.PrivateKey(decryptedRecovery[32:])
	msg := []byte("test message after recovery")
	sig := ed25519.Sign(recoveredSigningKey, msg)
	if !ed25519.Verify(sigKP.Public, msg, sig) {
		t.Fatal("signature with recovered key failed verification against original public key")
	}
}
