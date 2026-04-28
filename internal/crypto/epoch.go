package crypto

import (
	"crypto/ecdh"
	"encoding/binary"
	"fmt"
	"log/slog"
)

// EpochKeyPair represents an X25519 key pair for an epoch.
type EpochKeyPair struct {
	Epoch   uint64
	Private *ecdh.PrivateKey
	Public  *ecdh.PublicKey
}

// EncryptedEpochKey holds a previous epoch's private key encrypted under the
// next epoch's public key via X25519 ECDH + XChaCha20-Poly1305.
type EncryptedEpochKey struct {
	Epoch              uint64 // The epoch whose private key is encrypted
	EphemeralPubkey    []byte // Ephemeral public key used for ECDH with newPubKey
	EncryptedPrivKey   []byte // nonce || ciphertext of the previous epoch's private key
}

// GenerateEpochKey generates a new X25519 key pair for a given epoch.
func GenerateEpochKey(epoch uint64) (*EpochKeyPair, error) {
	kp, err := GenerateX25519KeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate epoch %d key: %w", epoch, err)
	}
	return &EpochKeyPair{
		Epoch:   epoch,
		Private: kp.Private,
		Public:  kp.Public,
	}, nil
}

// EncryptPreviousEpochKey encrypts the previous epoch's private key under the
// new epoch's public key using X25519 ECDH + XChaCha20-Poly1305.
// F-09 fix: userID is bound into the AAD to prevent cross-user epoch key
// substitution attacks. Pass nil for backward-compatible decryption of
// legacy epoch keys that were encrypted without user binding.
func EncryptPreviousEpochKey(prevPrivKey *ecdh.PrivateKey, prevEpoch uint64, newPubKey *ecdh.PublicKey, userID ...[]byte) (*EncryptedEpochKey, error) {
	// Generate ephemeral keypair for this encryption
	ephemeral, err := GenerateX25519KeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	// ECDH: ephemeral private x new public
	sharedSecret, err := ephemeral.Private.ECDH(newPubKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}
	defer ZeroBytes(sharedSecret)

	// Derive encryption key (salt = ephemeral public key for context binding)
	ephPubBytes := ephemeral.Public.Bytes()
	derivedKey, err := deriveKey(sharedSecret, ephPubBytes, "epoch-key-wrap")
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(derivedKey)

	// C4 FIX: Bind epoch number as AAD to prevent cross-epoch confusion.
	// F-09 fix: Also bind user ID to prevent cross-user epoch key substitution.
	// Audit fix F-04: Use length-prefixed encoding to prevent AAD collisions
	// between epoch number bytes and userID bytes.
	epochAAD := make([]byte, 8)
	binary.BigEndian.PutUint64(epochAAD, prevEpoch)
	if len(userID) > 0 && len(userID[0]) > 0 {
		uidLen := make([]byte, 4)
		binary.BigEndian.PutUint32(uidLen, uint32(len(userID[0])))
		epochAAD = append(epochAAD, uidLen...)
		epochAAD = append(epochAAD, userID[0]...)
	}

	// Encrypt the previous epoch's raw private key bytes
	prevKeyBytes := prevPrivKey.Bytes()
	defer ZeroBytes(prevKeyBytes)
	encrypted, err := sealXChaCha20(derivedKey, prevKeyBytes, epochAAD)
	if err != nil {
		return nil, fmt.Errorf("encrypt epoch key: %w", err)
	}

	return &EncryptedEpochKey{
		Epoch:            prevEpoch,
		EphemeralPubkey:  ephemeral.Public.Bytes(),
		EncryptedPrivKey: encrypted,
	}, nil
}

// DecryptEpochKey decrypts a previous epoch's private key using the current
// epoch's private key.
// F-09 fix: userID is verified in the AAD. For legacy epoch keys encrypted
// without user binding, pass nil — the function will try with user binding
// first, then fall back to epoch-only AAD for backward compatibility.
func DecryptEpochKey(enc *EncryptedEpochKey, currentPrivKey *ecdh.PrivateKey, userID ...[]byte) (*ecdh.PrivateKey, error) {
	// Validate ephemeral public key length.
	if len(enc.EphemeralPubkey) != 32 {
		return nil, fmt.Errorf("invalid ephemeral public key length: %d (expected 32)", len(enc.EphemeralPubkey))
	}
	ephemeralPub, err := ecdh.X25519().NewPublicKey(enc.EphemeralPubkey)
	if err != nil {
		return nil, fmt.Errorf("parse ephemeral public key: %w", err)
	}

	// ECDH: current private x ephemeral public
	sharedSecret, err := currentPrivKey.ECDH(ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}
	defer ZeroBytes(sharedSecret)

	// Derive decryption key (salt = ephemeral public key, matching encryption)
	derivedKey, err := deriveKey(sharedSecret, enc.EphemeralPubkey, "epoch-key-wrap")
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(derivedKey)

	// C4 FIX: Verify epoch number AAD matches.
	// F-09 fix: Also verify user ID in AAD. Try with user binding first,
	// then fall back to epoch-only AAD for backward compatibility with
	// legacy epoch keys encrypted before the user binding fix.
	epochAAD := make([]byte, 8)
	binary.BigEndian.PutUint64(epochAAD, enc.Epoch)

	// Audit fix F-04: Use length-prefixed encoding matching EncryptPreviousEpochKey.
	var privKeyBytes []byte
	if len(userID) > 0 && len(userID[0]) > 0 {
		uidLen := make([]byte, 4)
		binary.BigEndian.PutUint32(uidLen, uint32(len(userID[0])))
		userAAD := make([]byte, 0, len(epochAAD)+4+len(userID[0]))
		userAAD = append(userAAD, epochAAD...)
		userAAD = append(userAAD, uidLen...)
		userAAD = append(userAAD, userID[0]...)
		privKeyBytes, err = openXChaCha20(derivedKey, enc.EncryptedPrivKey, userAAD)
		if err != nil {
			// SECURITY: legacy fallback — try old AAD formats for pre-fix keys.
			// Audit fix F-05: Legacy fallback is only permitted for epochs created
			// before the length-prefixed AAD migration. Reject legacy AAD for any
			// epoch above the cutoff to prevent permanent downgrade.
			if enc.Epoch > LegacyAADMaxEpoch {
				return nil, fmt.Errorf("decrypt epoch key (legacy AAD rejected for epoch %d > cutoff %d): %w", enc.Epoch, LegacyAADMaxEpoch, err)
			}
			// Try pre-F-04 format (epoch || userID without length prefix).
			oldUserAAD := make([]byte, len(epochAAD)+len(userID[0]))
			copy(oldUserAAD, epochAAD)
			copy(oldUserAAD[len(epochAAD):], userID[0])
			privKeyBytes, err = openXChaCha20(derivedKey, enc.EncryptedPrivKey, oldUserAAD)
			if err != nil {
				// Try epoch-only AAD for pre-F-09 keys.
				privKeyBytes, err = openXChaCha20(derivedKey, enc.EncryptedPrivKey, epochAAD)
				if err != nil {
					return nil, fmt.Errorf("decrypt epoch key: %w", err)
				}
			}
			slog.Warn("epoch key decrypted with legacy AAD — schedule key rotation", "epoch", enc.Epoch)
		}
	} else {
		privKeyBytes, err = openXChaCha20(derivedKey, enc.EncryptedPrivKey, epochAAD)
		if err != nil {
			return nil, fmt.Errorf("decrypt epoch key: %w", err)
		}
	}
	defer ZeroBytes(privKeyBytes)

	// Reconstruct ecdh.PrivateKey
	privKey, err := ecdh.X25519().NewPrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse decrypted private key: %w", err)
	}

	return privKey, nil
}

// MaxEpochChainDepth is the maximum number of epoch links that can be
// traversed in a single chain. This prevents DoS via unbounded chains and
// limits the blast radius of a key compromise (audit fix F-01/F-05).
const MaxEpochChainDepth = 100

// LegacyAADMaxEpoch is the highest epoch number that may use the legacy
// (non-length-prefixed) AAD format during decryption. Epoch keys created
// after this cutoff MUST use the length-prefixed AAD introduced in audit
// fix F-04. Set this to the current max epoch at the time of deployment
// and never increase it, so the legacy fallback is eventually eliminated.
// Audit fix F-05: prevents permanent security downgrade via legacy AAD.
var LegacyAADMaxEpoch uint64 = 1000

// TraverseEpochChain walks backwards through an epoch chain, decrypting each
// previous epoch's private key in sequence. The chain should be ordered from
// most recent to oldest. Returns all decrypted private keys indexed by epoch.
// F-09 fix: userID is verified in the AAD for each link in the chain.
// Audit fix F-01/F-05: Rejects chains exceeding MaxEpochChainDepth.
func TraverseEpochChain(chain []EncryptedEpochKey, currentPrivKey *ecdh.PrivateKey, userID ...[]byte) (map[uint64]*ecdh.PrivateKey, error) {
	if len(chain) > MaxEpochChainDepth {
		return nil, fmt.Errorf("epoch chain too deep (%d links, max %d): break the chain by re-encrypting old messages", len(chain), MaxEpochChainDepth)
	}

	// Validate monotonically decreasing epoch numbers.
	for i := 1; i < len(chain); i++ {
		if chain[i].Epoch >= chain[i-1].Epoch {
			return nil, fmt.Errorf("epoch chain not monotonically decreasing: epoch[%d]=%d >= epoch[%d]=%d",
				i, chain[i].Epoch, i-1, chain[i-1].Epoch)
		}
	}

	keys := make(map[uint64]*ecdh.PrivateKey)
	privKey := currentPrivKey

	for i, enc := range chain {
		decrypted, err := DecryptEpochKey(&enc, privKey, userID...)
		if err != nil {
			// NOTE: ecdh.PrivateKey bytes cannot be zeroed in Go; mitigated by SGX enclave memory encryption.
			return nil, fmt.Errorf("decrypt epoch chain link %d (epoch %d): %w", i, enc.Epoch, err)
		}
		keys[enc.Epoch] = decrypted
		privKey = decrypted
	}

	return keys, nil
}
