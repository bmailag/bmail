//go:build js && wasm

package main

import (
	"fmt"
	"syscall/js"

	"github.com/bmailag/bmail/internal/crypto"
)

// ── Recovery ────────────────────────────────────────────────

func generateRecoveryMnemonic(args []js.Value) (interface{}, error) {
	mnemonic, err := crypto.GenerateMnemonic()
	if err != nil {
		return nil, err
	}
	return mnemonic, nil
}

func deriveRecoveryKey(args []js.Value) (interface{}, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("deriveRecoveryKey requires 1 arg: mnemonic")
	}
	mnemonic := args[0].String()
	key, err := crypto.DeriveRecoveryKey(mnemonic)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(key[:])
	return b64(key[:]), nil
}

func deriveRecoveryKeyV3(args []js.Value) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("deriveRecoveryKeyV3 requires 2 args: mnemonic, userID")
	}
	mnemonic := args[0].String()
	userID := args[1].String()
	key, err := crypto.DeriveRecoveryKeyV3(mnemonic, userID)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(key[:])
	return b64(key[:]), nil
}

func encryptWithRecoveryKey(args []js.Value) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("encryptWithRecoveryKey requires 2 args: recoveryKey, privateKey")
	}
	keyBytes, err := unb64(args[0].String())
	if err != nil {
		return nil, fmt.Errorf("decode recoveryKey: %w", err)
	}
	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("recovery key must be 32 bytes, got %d", len(keyBytes))
	}
	privKey, err := unb64(args[1].String())
	if err != nil {
		return nil, fmt.Errorf("decode privateKey: %w", err)
	}
	defer crypto.ZeroBytes(keyBytes)
	defer crypto.ZeroBytes(privKey)
	var key [32]byte
	copy(key[:], keyBytes)
	defer crypto.ZeroBytes(key[:])
	encrypted, err := crypto.EncryptWithRecoveryKey(privKey, key)
	if err != nil {
		return nil, err
	}
	return b64(encrypted), nil
}

func decryptWithRecoveryKey(args []js.Value) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("decryptWithRecoveryKey requires 2 args: recoveryKey, encryptedPrivateKey")
	}
	keyBytes, err := unb64(args[0].String())
	if err != nil {
		return nil, fmt.Errorf("decode recoveryKey: %w", err)
	}
	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("recovery key must be 32 bytes, got %d", len(keyBytes))
	}
	encrypted, err := unb64(args[1].String())
	if err != nil {
		return nil, fmt.Errorf("decode encryptedPrivateKey: %w", err)
	}
	defer crypto.ZeroBytes(keyBytes)
	var key [32]byte
	copy(key[:], keyBytes)
	defer crypto.ZeroBytes(key[:])
	decrypted, err := crypto.DecryptWithRecoveryKey(encrypted, key)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(decrypted)
	return b64(decrypted), nil
}

// ── OPAQUE Recovery Blob ────────────────────────────────────
// Encrypts/decrypts the recovery blob using the OPAQUE export key from the
// mnemonic-based OPAQUE credential. The key derivation uses a distinct
// salt/info to prevent key reuse with password-based encryption.

func encryptRecoveryBlob(args []js.Value) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("encryptRecoveryBlob requires 2 args: exportKey, privateKey")
	}
	exportKey, err := unb64(args[0].String())
	if err != nil {
		return nil, fmt.Errorf("decode exportKey: %w", err)
	}
	privKey, err := unb64(args[1].String())
	if err != nil {
		return nil, fmt.Errorf("decode privateKey: %w", err)
	}
	defer crypto.ZeroBytes(exportKey)
	defer crypto.ZeroBytes(privKey)
	encKey := deriveRecoveryEncKey(exportKey)
	defer crypto.ZeroBytes(encKey)
	encrypted, err := crypto.EncryptPrivateKey(privKey, encKey, crypto.AADRecoveryBlob)
	if err != nil {
		return nil, err
	}
	return b64(encrypted), nil
}

func decryptRecoveryBlob(args []js.Value) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("decryptRecoveryBlob requires 2 args: exportKey, encryptedBlob")
	}
	exportKey, err := unb64(args[0].String())
	if err != nil {
		return nil, fmt.Errorf("decode exportKey: %w", err)
	}
	encrypted, err := unb64(args[1].String())
	if err != nil {
		return nil, fmt.Errorf("decode encryptedBlob: %w", err)
	}
	defer crypto.ZeroBytes(exportKey)
	encKey := deriveRecoveryEncKey(exportKey)
	defer crypto.ZeroBytes(encKey)
	decrypted, err := crypto.DecryptPrivateKey(encrypted, encKey, crypto.AADRecoveryBlob)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(decrypted)
	return b64(decrypted), nil
}
