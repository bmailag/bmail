package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestGenerateX25519KeyPair(t *testing.T) {
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
	// X25519 public keys are 32 bytes
	if len(kp.Public.Bytes()) != 32 {
		t.Fatalf("expected 32-byte public key, got %d", len(kp.Public.Bytes()))
	}
}

func TestGenerateEd25519KeyPair(t *testing.T) {
	t.Parallel()
	kp, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair: %v", err)
	}
	if kp.Private == nil {
		t.Fatal("private key is nil")
	}
	if kp.Public == nil {
		t.Fatal("public key is nil")
	}
	if len(kp.Public) != 32 {
		t.Fatalf("expected 32-byte public key, got %d", len(kp.Public))
	}
	if len(kp.Private) != 64 {
		t.Fatalf("expected 64-byte private key, got %d", len(kp.Private))
	}
}

func TestEncryptDecryptPrivateKey_Roundtrip(t *testing.T) {
	t.Parallel()
	// Generate a key pair
	kp, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	originalBytes := kp.Private.Bytes()

	// Generate export key (32 bytes)
	exportKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(exportKey); err != nil {
		t.Fatalf("generate export key: %v", err)
	}

	// Encrypt with AAD
	encrypted, err := EncryptPrivateKey(originalBytes, exportKey, AADPrivateKey)
	if err != nil {
		t.Fatalf("EncryptPrivateKey: %v", err)
	}

	// Encrypted should be nonce (24) + plaintext (32) + tag (16) = 72 bytes
	expectedLen := chacha20poly1305.NonceSizeX + len(originalBytes) + chacha20poly1305.Overhead
	if len(encrypted) != expectedLen {
		t.Fatalf("expected %d bytes, got %d", expectedLen, len(encrypted))
	}

	// Decrypt with matching AAD
	decrypted, err := DecryptPrivateKey(encrypted, exportKey, AADPrivateKey)
	if err != nil {
		t.Fatalf("DecryptPrivateKey: %v", err)
	}

	if !bytes.Equal(originalBytes, decrypted) {
		t.Fatal("decrypted key does not match original")
	}
}

func TestDecryptPrivateKey_WrongKey(t *testing.T) {
	t.Parallel()
	kp, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	exportKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(exportKey); err != nil {
		t.Fatalf("generate export key: %v", err)
	}

	encrypted, err := EncryptPrivateKey(kp.Private.Bytes(), exportKey, AADPrivateKey)
	if err != nil {
		t.Fatalf("EncryptPrivateKey: %v", err)
	}

	// Try decrypting with a different key
	wrongKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(wrongKey); err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}

	_, err = DecryptPrivateKey(encrypted, wrongKey, AADPrivateKey)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong key")
	}
}

func TestDecryptPrivateKey_MismatchedAAD(t *testing.T) {
	t.Parallel()
	kp, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	exportKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(exportKey); err != nil {
		t.Fatalf("generate export key: %v", err)
	}

	encrypted, err := EncryptPrivateKey(kp.Private.Bytes(), exportKey, AADPrivateKey)
	if err != nil {
		t.Fatalf("EncryptPrivateKey: %v", err)
	}

	// Try decrypting with mismatched AAD — must fail (F-2 verification).
	_, err = DecryptPrivateKey(encrypted, exportKey, AADRecoveryKey)
	if err == nil {
		t.Fatal("expected error when decrypting with mismatched AAD")
	}

	// Also try with nil AAD — must fail.
	_, err = DecryptPrivateKey(encrypted, exportKey, nil)
	if err == nil {
		t.Fatal("expected error when decrypting with nil AAD")
	}
}

func TestEncryptPrivateKey_BadKeySize(t *testing.T) {
	t.Parallel()
	_, err := EncryptPrivateKey([]byte("data"), []byte("short"), AADPrivateKey)
	if err == nil {
		t.Fatal("expected error for short export key")
	}
}

func TestDecryptPrivateKey_BadKeySize(t *testing.T) {
	t.Parallel()
	_, err := DecryptPrivateKey(make([]byte, 72), []byte("short"), AADPrivateKey)
	if err == nil {
		t.Fatal("expected error for short export key")
	}
}

func TestDecryptPrivateKey_TooShort(t *testing.T) {
	t.Parallel()
	exportKey := make([]byte, chacha20poly1305.KeySize)
	_, err := DecryptPrivateKey([]byte("short"), exportKey, AADPrivateKey)
	if err == nil {
		t.Fatal("expected error for short encrypted data")
	}
}
