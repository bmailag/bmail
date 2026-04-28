// Package crypto implements core cryptographic primitives for Bmail encrypted email.
package crypto

import (
	"crypto/ed25519"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// X25519KeyPair holds an X25519 key pair for key exchange.
type X25519KeyPair struct {
	Private *ecdh.PrivateKey
	Public  *ecdh.PublicKey
}

// Ed25519KeyPair holds an Ed25519 key pair for signing.
type Ed25519KeyPair struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

// GenerateX25519KeyPair generates a new X25519 key pair using crypto/ecdh.
func GenerateX25519KeyPair() (*X25519KeyPair, error) {
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate X25519 key: %w", err)
	}
	return &X25519KeyPair{
		Private: privKey,
		Public:  privKey.PublicKey(),
	}, nil
}

// GenerateEd25519KeyPair generates a new Ed25519 key pair.
func GenerateEd25519KeyPair() (*Ed25519KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate Ed25519 key: %w", err)
	}
	return &Ed25519KeyPair{
		Private: priv,
		Public:  pub,
	}, nil
}

// EncryptPrivateKey encrypts a private key (raw bytes) using XChaCha20-Poly1305
// with the given 32-byte exportKey. The aad parameter provides additional
// authenticated data to bind the ciphertext to its intended purpose (F-2 fix).
// Returns nonce || ciphertext.
func EncryptPrivateKey(privateKeyBytes, exportKey, aad []byte) ([]byte, error) {
	if len(exportKey) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("export key must be %d bytes, got %d", chacha20poly1305.KeySize, len(exportKey))
	}

	aead, err := chacha20poly1305.NewX(exportKey)
	if err != nil {
		return nil, fmt.Errorf("create XChaCha20-Poly1305 cipher: %w", err)
	}

	nonce, err := secureNonce(chacha20poly1305.NonceSizeX) // 24 bytes
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, privateKeyBytes, aad)

	// Format: nonce || ciphertext
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result, nonce)
	copy(result[len(nonce):], ciphertext)

	return result, nil
}

// DecryptPrivateKey decrypts a private key encrypted with EncryptPrivateKey.
// The aad must match what was passed during encryption (F-2 fix).
// Input format: nonce (24 bytes) || ciphertext.
func DecryptPrivateKey(encrypted, exportKey, aad []byte) ([]byte, error) {
	if len(exportKey) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("export key must be %d bytes, got %d", chacha20poly1305.KeySize, len(exportKey))
	}

	if len(encrypted) < chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("encrypted data too short")
	}

	aead, err := chacha20poly1305.NewX(exportKey)
	if err != nil {
		return nil, fmt.Errorf("create XChaCha20-Poly1305 cipher: %w", err)
	}

	nonce := encrypted[:chacha20poly1305.NonceSizeX]
	ciphertext := encrypted[chacha20poly1305.NonceSizeX:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt private key: %w", err)
	}

	return plaintext, nil
}

// AAD constants for EncryptPrivateKey / DecryptPrivateKey context binding.
var (
	AADPrivateKey    = []byte("bmail-private-key-v1")
	AADPrivateKeyKEM = []byte("bmail-private-key-kem-v1")
	AADRecoveryKey   = []byte("bmail-recovery-key-v1")
	AADRecoveryBlob  = []byte("bmail-recovery-blob-v1") // OPAQUE-based recovery blob
)
