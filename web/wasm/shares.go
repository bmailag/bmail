//go:build js && wasm

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"syscall/js"

	"golang.org/x/crypto/pbkdf2"
)

// ── Drive Share AES-GCM helpers ────────────────────────────────
//
// These functions provide AES-256-GCM encryption matching the Web Crypto
// API format used by the web DriveShareModal so that mobile and web can
// produce/consume the same share blobs.
//
// Wire format: nonce (12 bytes) || ciphertext || tag (16 bytes)
// Inputs and outputs are base64-encoded.

// aesGcmEncryptShareJS encrypts a base64-encoded plaintext with a base64-
// encoded 32-byte AES-256-GCM key. Args: keyB64, plaintextB64.
// Returns base64(nonce || ciphertext || tag).
func aesGcmEncryptShareJS(args []js.Value) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("aesGcmEncryptShare requires 2 args: keyB64, plaintextB64")
	}
	key, err := unb64(args[0].String())
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: %d (expected 32)", len(key))
	}
	plaintext, err := unb64(args[1].String())
	if err != nil {
		return nil, fmt.Errorf("decode plaintext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}
	// Seal appends ciphertext+tag to nonce.
	out := gcm.Seal(nonce, nonce, plaintext, nil)
	return b64(out), nil
}

// aesGcmDecryptShareJS decrypts a base64(nonce || ciphertext || tag) blob
// with a base64-encoded 32-byte AES-256-GCM key. Args: keyB64, blobB64.
// Returns base64-encoded plaintext.
func aesGcmDecryptShareJS(args []js.Value) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("aesGcmDecryptShare requires 2 args: keyB64, blobB64")
	}
	key, err := unb64(args[0].String())
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: %d (expected 32)", len(key))
	}
	blob, err := unb64(args[1].String())
	if err != nil {
		return nil, fmt.Errorf("decode blob: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	if len(blob) < gcm.NonceSize()+gcm.Overhead() {
		return nil, fmt.Errorf("blob too short")
	}
	nonce := blob[:gcm.NonceSize()]
	ct := blob[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("gcm.Open: %w", err)
	}
	return b64(plaintext), nil
}

// pbkdf2DeriveShareKeyJS derives a 32-byte AES-256-GCM key from a password
// using PBKDF2-HMAC-SHA256. Matches the parameters used by the web
// DriveShareModal: 100,000 iterations, SHA-256, 256-bit output.
// Args: password (UTF-8 string), saltB64. Returns base64-encoded 32-byte key.
func pbkdf2DeriveShareKeyJS(args []js.Value) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("pbkdf2DeriveShareKey requires 2 args: password, saltB64")
	}
	password := args[0].String()
	salt, err := unb64(args[1].String())
	if err != nil {
		return nil, fmt.Errorf("decode salt: %w", err)
	}
	key := pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)
	return b64(key), nil
}

// generateRandomBytesJS returns N cryptographically random bytes as base64.
// Used by mobile to generate share tokens and salts without needing a
// JS-side CSPRNG polyfill.
func generateRandomBytesJS(args []js.Value) (interface{}, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("generateRandomBytes requires 1 arg: length")
	}
	n := args[0].Int()
	if n <= 0 || n > 1024 {
		return nil, fmt.Errorf("invalid length: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, fmt.Errorf("read random: %w", err)
	}
	return b64(buf), nil
}
