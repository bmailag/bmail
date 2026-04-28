//go:build js && wasm

package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"syscall/js"

	"golang.org/x/crypto/hkdf"

	"github.com/bmailag/bmail/internal/crypto"
)

// deriveEncKeyV1 derives a 32-byte encryption key from the OPAQUE export key
// using HKDF-SHA256 with nil salt (legacy).
//
// DEPRECATION: This function exists only for backward compatibility.
// Accounts still using V1 key derivation should be prompted to change their
// password, which will re-encrypt with V2 (salted HKDF). V1 support should
// be removed once all accounts have migrated.
func deriveEncKeyV1(exportKey []byte) []byte {
	reader := hkdf.New(sha256.New, exportKey, nil, []byte("bmail-opaque-enc-key-v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(reader, key); err != nil {
		panic("deriveEncKeyV1: HKDF failed: " + err.Error())
	}
	return key
}

// deriveEncKey derives a 32-byte encryption key from the OPAQUE export key
// (which may be 64 bytes) using HKDF-SHA256 with a domain-separated salt.
// New registrations use this version exclusively.
func deriveEncKey(exportKey []byte) []byte {
	reader := hkdf.New(sha256.New, exportKey, []byte("bmail-opaque-enc-salt-v1"), []byte("bmail-opaque-enc-key-v2"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(reader, key); err != nil {
		panic("deriveEncKey: HKDF failed: " + err.Error())
	}
	return key
}

// deriveRecoveryEncKey derives a 32-byte encryption key from the OPAQUE export key
// for encrypting the recovery blob. Uses a distinct salt/info to prevent key reuse
// with the password-based private key encryption.
func deriveRecoveryEncKey(exportKey []byte) []byte {
	reader := hkdf.New(sha256.New, exportKey, []byte("bmail-opaque-recovery-salt-v1"), []byte("bmail-opaque-recovery-enc-key-v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(reader, key); err != nil {
		panic("deriveRecoveryEncKey: HKDF failed: " + err.Error())
	}
	return key
}

// ── Key Generation ───────────────────────────────────────────

func generateKeypair(args []js.Value) (interface{}, error) {
	encKP, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate encryption keypair: %w", err)
	}
	sigKP, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate signing keypair: %w", err)
	}
	kemKP, err := crypto.GenerateMLKEMKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate ML-KEM-768 keypair: %w", err)
	}

	return toJSObject(map[string]interface{}{
		"publicKeyEncryption":  b64(encKP.Public.Bytes()),
		"privateKeyEncryption": b64(encKP.Private.Bytes()),
		"publicKeySigning":     b64(sigKP.Public),
		"privateKeySigning":    b64(sigKP.Private),
		"publicKeyKEM":         b64(kemKP.EncapsulationKey.Bytes()),
		"privateKeyKEM":        b64(kemKP.DecapsulationKey.Bytes()),
	}), nil
}

// generateKEMUpgrade generates a new ML-KEM-768 keypair for an existing user
// who doesn't have one yet. The export key (from OPAQUE login) is used to
// encrypt the decapsulation key. Called post-login when the user's profile
// shows no public_key_kem.
// Args: exportKeyB64 (string)
// Returns: { public_key_kem, encrypted_private_key_kem }
func generateKEMUpgrade(args []js.Value) (interface{}, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("generateKEMUpgrade requires 1 arg: exportKeyB64")
	}
	encKey, err := unb64(args[0].String())
	if err != nil {
		return nil, fmt.Errorf("decode export key: %w", err)
	}
	defer crypto.ZeroBytes(encKey)

	kemKP, err := crypto.GenerateMLKEMKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate ML-KEM-768 keypair: %w", err)
	}

	encryptedKEMPriv, err := crypto.EncryptPrivateKey(kemKP.DecapsulationKey.Bytes(), encKey, crypto.AADPrivateKeyKEM)
	if err != nil {
		return nil, fmt.Errorf("encrypt KEM private key: %w", err)
	}

	return toJSObject(map[string]interface{}{
		"public_key_kem":             b64(kemKP.EncapsulationKey.Bytes()),
		"encrypted_private_key_kem":  b64(encryptedKEMPriv),
		"private_key_kem":            b64(kemKP.DecapsulationKey.Bytes()),
	}), nil
}

func encryptPrivateKey(args []js.Value) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("encryptPrivateKey requires 2 args: exportKey, privateKey")
	}
	exportKey, err := unb64(args[0].String())
	if err != nil {
		return nil, fmt.Errorf("decode exportKey: %w", err)
	}
	defer crypto.ZeroBytes(exportKey)
	privKey, err := unb64(args[1].String())
	if err != nil {
		return nil, fmt.Errorf("decode privateKey: %w", err)
	}
	defer crypto.ZeroBytes(privKey)
	encrypted, err := crypto.EncryptPrivateKey(privKey, exportKey, crypto.AADPrivateKey)
	if err != nil {
		return nil, err
	}
	return b64(encrypted), nil
}

func decryptPrivateKey(args []js.Value) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("decryptPrivateKey requires 2 args: exportKey, encryptedPrivateKey")
	}
	exportKey, err := unb64(args[0].String())
	if err != nil {
		return nil, fmt.Errorf("decode exportKey: %w", err)
	}
	defer crypto.ZeroBytes(exportKey)
	encrypted, err := unb64(args[1].String())
	if err != nil {
		return nil, fmt.Errorf("decode encryptedPrivateKey: %w", err)
	}
	privKey, err := crypto.DecryptPrivateKey(encrypted, exportKey, crypto.AADPrivateKey)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(privKey)
	return b64(privKey), nil
}

func decryptPrivateKeyKEM(args []js.Value) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("decryptPrivateKeyKEM requires 2 args: derivedEncKey, encryptedKEMPrivateKey")
	}
	encKey, err := unb64(args[0].String())
	if err != nil {
		return nil, fmt.Errorf("decode encKey: %w", err)
	}
	defer crypto.ZeroBytes(encKey)
	encrypted, err := unb64(args[1].String())
	if err != nil {
		return nil, fmt.Errorf("decode encryptedKEMPrivateKey: %w", err)
	}
	privKey, err := crypto.DecryptPrivateKey(encrypted, encKey, crypto.AADPrivateKeyKEM)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(privKey)
	return b64(privKey), nil
}
