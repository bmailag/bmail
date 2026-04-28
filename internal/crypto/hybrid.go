package crypto

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"fmt"
)

const (
	// EnvelopeVersionHybrid is the version byte prefix for hybrid X25519 + ML-KEM-768 envelopes.
	EnvelopeVersionHybrid byte = 0x02

	// HybridEnvelopeKeySize is the total size of a hybrid envelope key:
	// version(1) + X25519 ephemeral pubkey(32) + ML-KEM-768 ciphertext(1088).
	HybridEnvelopeKeySize = 1 + 32 + MLKEMCiphertextSize // 1121

	classicalEphKeySize = 32
)

// hybridWrap performs the hybrid X25519 + ML-KEM-768 key encapsulation,
// returning the envelope key and the wrapped message key.
func hybridWrap(x25519Pub *ecdh.PublicKey, kemEK *mlkem.EncapsulationKey768, messageKey []byte) (envelopeKey, encryptedMessageKey []byte, err error) {
	// 1. Ephemeral X25519 keypair + ECDH
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ephemeral key: %w", err)
	}
	x25519SS, err := ephemeral.ECDH(x25519Pub)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDH: %w", err)
	}
	defer ZeroBytes(x25519SS)

	// 2. ML-KEM-768 encapsulation
	kemSS, kemCT := kemEK.Encapsulate()
	defer ZeroBytes(kemSS)

	// 3. Build envelope key: version || eph_pub || kem_ct
	ephPubBytes := ephemeral.PublicKey().Bytes()
	envelopeKey = make([]byte, HybridEnvelopeKeySize)
	envelopeKey[0] = EnvelopeVersionHybrid
	copy(envelopeKey[1:33], ephPubBytes)
	copy(envelopeKey[33:], kemCT)

	// 4. Combined shared secret: x25519_ss || kem_ss
	combinedSS := make([]byte, len(x25519SS)+len(kemSS))
	copy(combinedSS, x25519SS)
	copy(combinedSS[len(x25519SS):], kemSS)
	defer ZeroBytes(combinedSS)

	// 5. HKDF: salt = eph_pub || kem_ct, info = "message-key-wrap-v2"
	salt := envelopeKey[1:] // eph_pub(32) || kem_ct(1088)
	wrapKey, err := deriveKey(combinedSS, salt, "message-key-wrap-v2")
	if err != nil {
		return nil, nil, err
	}
	defer ZeroBytes(wrapKey)

	// 6. Seal message key with AAD = full envelope key (binds version + both key materials)
	encryptedMessageKey, err = sealXChaCha20(wrapKey, messageKey, envelopeKey)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt message key: %w", err)
	}

	return envelopeKey, encryptedMessageKey, nil
}

// hybridUnwrap decapsulates a hybrid envelope, recovering the message key.
func hybridUnwrap(x25519Priv *ecdh.PrivateKey, kemDK *mlkem.DecapsulationKey768, envelopeKey, encryptedMessageKey []byte) ([]byte, error) {
	if len(envelopeKey) != HybridEnvelopeKeySize {
		return nil, fmt.Errorf("invalid hybrid envelope key length: %d (expected %d)", len(envelopeKey), HybridEnvelopeKeySize)
	}
	if envelopeKey[0] != EnvelopeVersionHybrid {
		return nil, fmt.Errorf("not a hybrid envelope (version byte 0x%02x)", envelopeKey[0])
	}

	// Parse envelope key components.
	ephPubBytes := envelopeKey[1:33]
	kemCT := envelopeKey[33:]

	// 1. X25519 ECDH
	ephPub, err := ecdh.X25519().NewPublicKey(ephPubBytes)
	if err != nil {
		return nil, fmt.Errorf("parse ephemeral public key: %w", err)
	}
	x25519SS, err := x25519Priv.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}
	defer ZeroBytes(x25519SS)

	// 2. ML-KEM-768 decapsulation
	kemSS, err := kemDK.Decapsulate(kemCT)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM decapsulate: %w", err)
	}
	defer ZeroBytes(kemSS)

	// 3. Combined shared secret
	combinedSS := make([]byte, len(x25519SS)+len(kemSS))
	copy(combinedSS, x25519SS)
	copy(combinedSS[len(x25519SS):], kemSS)
	defer ZeroBytes(combinedSS)

	// 4. HKDF
	salt := envelopeKey[1:]
	wrapKey, err := deriveKey(combinedSS, salt, "message-key-wrap-v2")
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(wrapKey)

	// 5. Open message key
	messageKey, err := openXChaCha20(wrapKey, encryptedMessageKey, envelopeKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt message key: %w", err)
	}
	return messageKey, nil
}

// classicalUnwrap performs the existing classical X25519 envelope unwrap.
func classicalUnwrap(x25519Priv *ecdh.PrivateKey, ephPubBytes, encryptedMessageKey []byte) ([]byte, error) {
	ephPub, err := ecdh.X25519().NewPublicKey(ephPubBytes)
	if err != nil {
		return nil, fmt.Errorf("parse ephemeral public key: %w", err)
	}
	sharedSecret, err := x25519Priv.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}
	defer ZeroBytes(sharedSecret)

	derivedKey, err := deriveKey(sharedSecret, ephPubBytes, "message-key-wrap")
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(derivedKey)

	messageKey, err := openXChaCha20(derivedKey, encryptedMessageKey, ephPubBytes)
	if err != nil {
		return nil, fmt.Errorf("decrypt message key: %w", err)
	}
	return messageKey, nil
}

// UnwrapEnvelope auto-detects the envelope format and unwraps the message key.
//
// Format detection:
//   - len == 32: legacy classical (raw X25519 ephemeral pubkey)
//   - [0] == 0x02 && len == 1121: hybrid X25519 + ML-KEM-768
//
// If the envelope is hybrid but kemDK is nil, returns an error.
func UnwrapEnvelope(x25519Priv *ecdh.PrivateKey, kemDK *mlkem.DecapsulationKey768, envelopeKey, encryptedMessageKey []byte) ([]byte, error) {
	return unwrapEnvelope(x25519Priv, kemDK, envelopeKey, encryptedMessageKey)
}

func unwrapEnvelope(x25519Priv *ecdh.PrivateKey, kemDK *mlkem.DecapsulationKey768, envelopeKey, encryptedMessageKey []byte) ([]byte, error) {
	switch {
	case len(envelopeKey) == classicalEphKeySize:
		return classicalUnwrap(x25519Priv, envelopeKey, encryptedMessageKey)

	case len(envelopeKey) == HybridEnvelopeKeySize && envelopeKey[0] == EnvelopeVersionHybrid:
		if kemDK == nil {
			return nil, fmt.Errorf("hybrid envelope requires ML-KEM decapsulation key")
		}
		return hybridUnwrap(x25519Priv, kemDK, envelopeKey, encryptedMessageKey)

	default:
		return nil, fmt.Errorf("unrecognized envelope key format (length %d)", len(envelopeKey))
	}
}

// WrapEnvelope auto-selects classical or hybrid wrapping based on whether
// a KEM encapsulation key is provided.
func WrapEnvelope(x25519Pub *ecdh.PublicKey, kemEK *mlkem.EncapsulationKey768, messageKey []byte) (envelopeKey, encryptedMessageKey []byte, err error) {
	return wrapEnvelope(x25519Pub, kemEK, messageKey)
}

func wrapEnvelope(x25519Pub *ecdh.PublicKey, kemEK *mlkem.EncapsulationKey768, messageKey []byte) (envelopeKey, encryptedMessageKey []byte, err error) {
	if kemEK != nil {
		return hybridWrap(x25519Pub, kemEK, messageKey)
	}
	return classicalWrap(x25519Pub, messageKey)
}

// classicalWrap performs the classical X25519-only envelope wrap.
func classicalWrap(x25519Pub *ecdh.PublicKey, messageKey []byte) (envelopeKey, encryptedMessageKey []byte, err error) {
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ephemeral key: %w", err)
	}
	sharedSecret, err := ephemeral.ECDH(x25519Pub)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDH: %w", err)
	}
	defer ZeroBytes(sharedSecret)

	ephPubBytes := ephemeral.PublicKey().Bytes()
	derivedKey, err := deriveKey(sharedSecret, ephPubBytes, "message-key-wrap")
	if err != nil {
		return nil, nil, err
	}
	defer ZeroBytes(derivedKey)

	encryptedMessageKey, err = sealXChaCha20(derivedKey, messageKey, ephPubBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt message key: %w", err)
	}
	return ephPubBytes, encryptedMessageKey, nil
}
