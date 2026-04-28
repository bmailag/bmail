package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/tyler-smith/go-bip39"
)

// GenerateMnemonic generates a new BIP-39 mnemonic phrase (24 words / 256 bits of entropy).
//
// Entropy source audit (go-bip39 v1.1.0, bip39.go line 99-108):
//   NewEntropy(bitSize) calls crypto/rand.Read(entropy) — verified CSPRNG.
//   No fallback to math/rand or other weak sources. Safe to use directly.
func GenerateMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", fmt.Errorf("generate entropy: %w", err)
	}
	defer ZeroBytes(entropy)
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("generate mnemonic: %w", err)
	}
	return mnemonic, nil
}

// DeriveRecoveryKey derives a 32-byte recovery key from a BIP-39 mnemonic using
// HKDF-SHA256 with domain separation. Recovery mnemonics are NOT compatible with
// cryptocurrency wallets (intentional — this is a mail recovery key, not a wallet seed).
// Uses V2 derivation (not user-bound) for backward compatibility.
func DeriveRecoveryKey(mnemonic string) ([32]byte, error) {
	entropy, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return [32]byte{}, fmt.Errorf("extract entropy from mnemonic: %w", err)
	}
	defer ZeroBytes(entropy)
	return deriveRecoveryKeyV2(entropy)
}

// DeriveRecoveryKeyV3 derives a user-bound recovery key. The userID (email or UUID)
// is mixed into the HKDF info parameter so that a leaked mnemonic cannot be used
// to attempt recovery against arbitrary accounts (audit fix F-06).
// New registrations should use V3; existing users are migrated on next recovery.
func DeriveRecoveryKeyV3(mnemonic string, userID string) ([32]byte, error) {
	if userID == "" {
		return [32]byte{}, fmt.Errorf("userID required for V3 recovery key derivation")
	}
	entropy, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return [32]byte{}, fmt.Errorf("extract entropy from mnemonic: %w", err)
	}
	defer ZeroBytes(entropy)
	reader := hkdf.New(sha256.New, entropy, []byte("bmail-recovery-salt-v1"), []byte("bmail-recovery-key-v3:"+userID))
	var key [32]byte
	if _, err := io.ReadFull(reader, key[:]); err != nil {
		return [32]byte{}, fmt.Errorf("derive recovery key v3: %w", err)
	}
	return key, nil
}

// deriveRecoveryKeyV2 uses HKDF-SHA256 with domain separation and a fixed salt
// for proper KDF usage. The salt improves entropy extraction from the input
// keying material (F-3 fix).
func deriveRecoveryKeyV2(entropy []byte) ([32]byte, error) {
	reader := hkdf.New(sha256.New, entropy, []byte("bmail-recovery-salt-v1"), []byte("bmail-recovery-key-v2"))
	var key [32]byte
	if _, err := io.ReadFull(reader, key[:]); err != nil {
		return [32]byte{}, fmt.Errorf("derive recovery key: %w", err)
	}
	return key, nil
}

// EncryptWithRecoveryKey encrypts data using XChaCha20-Poly1305 with a recovery key.
// Uses AAD to bind ciphertext to the recovery context (F-2 fix).
// Returns nonce || ciphertext.
func EncryptWithRecoveryKey(plaintext []byte, recoveryKey [32]byte) ([]byte, error) {
	return sealXChaCha20(recoveryKey[:], plaintext, AADRecoveryKey)
}

// DecryptWithRecoveryKey decrypts data encrypted with EncryptWithRecoveryKey.
// Input format: nonce (24 bytes) || ciphertext.
func DecryptWithRecoveryKey(encrypted []byte, recoveryKey [32]byte) ([]byte, error) {
	return openXChaCha20(recoveryKey[:], encrypted, AADRecoveryKey)
}
