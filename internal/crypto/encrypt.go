package crypto

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// nonceCounter is a monotonically increasing counter mixed into every nonce.
// Even if the RNG produces identical output twice (catastrophic but theoretically
// possible), the counter ensures distinct nonces. Uses atomic to be safe for
// concurrent use across goroutines.
//
// Seeded from crypto/rand to prevent predictability (F-5 fix).
// Audit fix F-13: 16 bytes of entropy prevents collisions across multiple
// instances that start simultaneously (birthday bound ~2^64 for uint64).
var nonceCounter = func() uint64 {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		log.Fatal("crypto/rand failed during init: " + err.Error())
	}
	// XOR both halves for maximum entropy in a single uint64.
	a := binary.LittleEndian.Uint64(buf[:8])
	b := binary.LittleEndian.Uint64(buf[8:])
	return a ^ b
}()

// EncryptedMessage holds all components of an encrypted message.
type EncryptedMessage struct {
	EphemeralPubkey     []byte // Raw X25519 public key bytes
	EncryptedMessageKey []byte // nonce || ciphertext (message key encrypted with derived key)
	EncryptedBody       []byte // nonce || ciphertext (body encrypted with message key)
	EncryptedSubject    []byte // nonce || ciphertext (subject encrypted with message key)
	EncryptedHeaders    []byte // nonce || ciphertext (headers JSON encrypted with the SAME message key, AAD "headers"). Phase B3: replaces the per-field encrypted address columns. Optional — empty for messages that pre-date B3 or for transient envelopes (e.g. EncryptAddressForUser).
}

// secureNonce generates a cryptographically random nonce of the given size
// using crypto/rand and validates that the result is not all zeros (which
// would indicate a catastrophic RNG failure).
func secureNonce(size int) ([]byte, error) {
	nonce := make([]byte, size)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("read crypto/rand: %w", err)
	}

	// Audit fix F-15: Check for all-zero RNG output BEFORE mixing in the
	// counter, so a broken RNG is detected rather than silently masked.
	allZero := true
	for _, b := range nonce {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, fmt.Errorf("crypto/rand returned all-zero nonce (%d bytes); RNG may be broken", size)
	}

	// Mix in a monotonic counter to guarantee uniqueness even under RNG
	// duplication. The counter is XOR'd into the first 8 bytes so it
	// doesn't reduce randomness — it only adds distinctness.
	if size >= 8 {
		ctr := atomic.AddUint64(&nonceCounter, 1)
		existing := binary.LittleEndian.Uint64(nonce[:8])
		binary.LittleEndian.PutUint64(nonce[:8], existing^ctr)
	}

	return nonce, nil
}

// secureKey generates cryptographically random key material of the given size
// using crypto/rand without counter mixing. Unlike secureNonce, this preserves
// full entropy for symmetric key generation (audit fix F-16).
func secureKey(size int) ([]byte, error) {
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("read crypto/rand: %w", err)
	}
	// Verify not all zeros — signals a broken RNG.
	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, fmt.Errorf("crypto/rand returned all-zero key (%d bytes); RNG may be broken", size)
	}
	return key, nil
}

// sealXChaCha20 encrypts plaintext with XChaCha20-Poly1305 using the given key.
// The optional aad (additional authenticated data) is authenticated but not
// encrypted — use it to bind ciphertext to contextual data (e.g. an ephemeral
// public key) so that tampering with the context is detected on decryption.
// Returns nonce || ciphertext.
func sealXChaCha20(key, plaintext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("create XChaCha20-Poly1305: %w", err)
	}

	nonce, err := secureNonce(chacha20poly1305.NonceSizeX)
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result, nonce)
	copy(result[len(nonce):], ciphertext)
	return result, nil
}

// openXChaCha20 decrypts data encrypted by sealXChaCha20.
// The same aad that was passed to sealXChaCha20 must be provided; if it
// differs, decryption will fail with an authentication error.
// Input format: nonce (24 bytes) || ciphertext.
func openXChaCha20(key, encrypted, aad []byte) ([]byte, error) {
	if len(encrypted) < chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("encrypted data too short")
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("create XChaCha20-Poly1305: %w", err)
	}

	nonce := encrypted[:chacha20poly1305.NonceSizeX]
	ciphertext := encrypted[chacha20poly1305.NonceSizeX:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

// deriveKey derives a 32-byte key from a shared secret using HKDF-SHA256.
// The salt parameter binds the derivation to a specific context (typically the
// ephemeral public key), improving entropy extraction from the shared secret.
func deriveKey(sharedSecret, salt []byte, info string) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, sharedSecret, salt, []byte(info))
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("HKDF derive key: %w", err)
	}
	return key, nil
}

// DeriveWrapKey derives the 32-byte AEAD wrap key from an X25519 shared
// secret using the same HKDF parameters as the standard EncryptMessage
// envelope ("message-key-wrap" info, ephemeral pubkey as salt). Exported
// so the WASM bridge can implement standalone wrap/unwrap helpers
// (used by the Phase B FCK share flow).
func DeriveWrapKey(sharedSecret, ephemeralPubkey []byte) ([]byte, error) {
	return deriveKey(sharedSecret, ephemeralPubkey, "message-key-wrap")
}

// SealWrappedKey encrypts a 32-byte message_key under the wrap key
// derived from an ECDH shared secret. The ephemeral pubkey is bound
// as AAD so a tampered envelope fails authentication.
func SealWrappedKey(wrapKey, messageKey, ephemeralPubkey []byte) ([]byte, error) {
	return sealXChaCha20(wrapKey, messageKey, ephemeralPubkey)
}

// OpenWrappedKey is the inverse of SealWrappedKey: it decrypts a
// wrapped message_key under the wrap key derived from the recipient's
// ECDH(privKey, ephPub) shared secret.
func OpenWrappedKey(wrapKey, encrypted, ephemeralPubkey []byte) ([]byte, error) {
	return openXChaCha20(wrapKey, encrypted, ephemeralPubkey)
}

// EncryptMessage encrypts a message (subject + body) for a recipient's X25519 public key.
//
// Algorithm:
//  1. Generate random 32-byte message_key
//  2. Generate ephemeral X25519 keypair
//  3. shared_secret = X25519(ephemeral_private, recipient_public)
//  4. derived_key = HKDF-SHA256(shared_secret, "message-key-wrap")
//  5. encrypted_message_key = XChaCha20-Poly1305(derived_key, message_key)
//  6. encrypted_body = XChaCha20-Poly1305(message_key, body)
//  7. encrypted_subject = XChaCha20-Poly1305(message_key, subject)
func EncryptMessage(recipientPub *ecdh.PublicKey, subject, body []byte) (*EncryptedMessage, error) {
	// 1. Generate random message key (audit fix F-16: use secureKey, not
	// secureNonce, to preserve full 256-bit entropy without counter mixing).
	messageKey, err := secureKey(32)
	if err != nil {
		return nil, fmt.Errorf("generate message key: %w", err)
	}
	defer ZeroBytes(messageKey)

	// 2. Generate ephemeral X25519 keypair
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	// 3. ECDH shared secret
	sharedSecret, err := ephemeral.ECDH(recipientPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}
	defer ZeroBytes(sharedSecret)

	// 4. Derive key via HKDF (salt = ephemeral public key for context binding)
	ephPubBytes := ephemeral.PublicKey().Bytes()
	derivedKey, err := deriveKey(sharedSecret, ephPubBytes, "message-key-wrap")
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(derivedKey)

	// 5. Encrypt message key (AAD = ephemeral public key to bind ciphertext to this key exchange)
	encryptedMessageKey, err := sealXChaCha20(derivedKey, messageKey, ephPubBytes)
	if err != nil {
		return nil, fmt.Errorf("encrypt message key: %w", err)
	}

	// 6. Encrypt body (AAD = "body" to prevent body/subject ciphertext swapping)
	encryptedBody, err := sealXChaCha20(messageKey, body, []byte("body"))
	if err != nil {
		return nil, fmt.Errorf("encrypt body: %w", err)
	}

	// 7. Encrypt subject (AAD = "subject" to prevent body/subject ciphertext swapping)
	encryptedSubject, err := sealXChaCha20(messageKey, subject, []byte("subject"))
	if err != nil {
		return nil, fmt.Errorf("encrypt subject: %w", err)
	}

	return &EncryptedMessage{
		EphemeralPubkey:     ephemeral.PublicKey().Bytes(),
		EncryptedMessageKey: encryptedMessageKey,
		EncryptedBody:       encryptedBody,
		EncryptedSubject:    encryptedSubject,
	}, nil
}

// DecryptMessage decrypts an EncryptedMessage using the recipient's X25519 private key.
func DecryptMessage(recipientPriv *ecdh.PrivateKey, msg *EncryptedMessage) (subject, body []byte, err error) {
	// Validate ephemeral public key length before parsing.
	if len(msg.EphemeralPubkey) != 32 {
		return nil, nil, fmt.Errorf("invalid ephemeral public key length: %d (expected 32)", len(msg.EphemeralPubkey))
	}
	ephemeralPub, err := ecdh.X25519().NewPublicKey(msg.EphemeralPubkey)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ephemeral public key: %w", err)
	}

	// ECDH shared secret
	sharedSecret, err := recipientPriv.ECDH(ephemeralPub)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDH: %w", err)
	}
	defer ZeroBytes(sharedSecret)

	// Derive key (salt = ephemeral public key, matching encryption)
	derivedKey, err := deriveKey(sharedSecret, msg.EphemeralPubkey, "message-key-wrap")
	if err != nil {
		return nil, nil, err
	}
	defer ZeroBytes(derivedKey)

	// Decrypt message key (AAD = ephemeral public key, must match what was used in Seal)
	messageKey, err := openXChaCha20(derivedKey, msg.EncryptedMessageKey, msg.EphemeralPubkey)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt message key: %w", err)
	}
	defer ZeroBytes(messageKey)

	// Decrypt body (AAD = "body" must match encryption)
	body, err = openXChaCha20(messageKey, msg.EncryptedBody, []byte("body"))
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt body: %w", err)
	}

	// Decrypt subject (AAD = "subject" must match encryption).
	// Empty EncryptedSubject means there is no subject ciphertext at all
	// (e.g. drive file downloads, where the encrypted name is fetched
	// separately from the listing). Return nil instead of failing.
	if len(msg.EncryptedSubject) > 0 {
		subject, err = openXChaCha20(messageKey, msg.EncryptedSubject, []byte("subject"))
		if err != nil {
			return nil, nil, fmt.Errorf("decrypt subject: %w", err)
		}
	}

	return subject, body, nil
}

// DecryptSubjectOnly decrypts just the subject without requiring the body.
func DecryptSubjectOnly(recipientPriv *ecdh.PrivateKey, ephemeralPubkey, encryptedMessageKey, encryptedSubject []byte) ([]byte, error) {
	if len(ephemeralPubkey) != 32 {
		return nil, fmt.Errorf("invalid ephemeral public key length: %d", len(ephemeralPubkey))
	}
	ephPub, err := ecdh.X25519().NewPublicKey(ephemeralPubkey)
	if err != nil {
		return nil, fmt.Errorf("parse ephemeral public key: %w", err)
	}

	sharedSecret, err := recipientPriv.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}
	defer ZeroBytes(sharedSecret)

	derivedKey, err := deriveKey(sharedSecret, ephemeralPubkey, "message-key-wrap")
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(derivedKey)

	messageKey, err := openXChaCha20(derivedKey, encryptedMessageKey, ephemeralPubkey)
	if err != nil {
		return nil, fmt.Errorf("decrypt message key: %w", err)
	}
	defer ZeroBytes(messageKey)

	subject, err := openXChaCha20(messageKey, encryptedSubject, []byte("subject"))
	if err != nil {
		return nil, fmt.Errorf("decrypt subject: %w", err)
	}
	return subject, nil
}

// DecryptHeaders decrypts the headers slot of an EncryptedMessage
// using the same envelope that wraps the body. The plaintext is the
// JSON blob produced by EncryptMessageWithHeaders (Phase B3 format)
// — typically a small `{"Headers": {"From": [...], "To": [...]}}`
// document parsed from the inbound RFC 5322 message.
//
// Returns the raw JSON bytes; the caller is responsible for parsing.
func DecryptHeaders(recipientPriv *ecdh.PrivateKey, ephemeralPubkey, encryptedMessageKey, encryptedHeaders []byte) ([]byte, error) {
	if len(encryptedHeaders) == 0 {
		return nil, fmt.Errorf("encrypted headers are empty")
	}
	if len(ephemeralPubkey) != 32 {
		return nil, fmt.Errorf("invalid ephemeral public key length: %d", len(ephemeralPubkey))
	}
	ephPub, err := ecdh.X25519().NewPublicKey(ephemeralPubkey)
	if err != nil {
		return nil, fmt.Errorf("parse ephemeral public key: %w", err)
	}
	sharedSecret, err := recipientPriv.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}
	defer ZeroBytes(sharedSecret)

	derivedKey, err := deriveKey(sharedSecret, ephemeralPubkey, "message-key-wrap")
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(derivedKey)

	messageKey, err := openXChaCha20(derivedKey, encryptedMessageKey, ephemeralPubkey)
	if err != nil {
		return nil, fmt.Errorf("decrypt message key: %w", err)
	}
	defer ZeroBytes(messageKey)

	headers, err := openXChaCha20(messageKey, encryptedHeaders, []byte("headers"))
	if err != nil {
		return nil, fmt.Errorf("decrypt headers: %w", err)
	}
	return headers, nil
}

// EncryptMessageWithHeaders encrypts a subject + body + headers JSON
// for a recipient's X25519 public key. All three slots share the same
// random message key (and therefore the same envelope), so the client
// only has to unwrap the key once and can decrypt any of the three
// independently — same trick the existing EncryptMessage uses for
// subject vs body, extended with a "headers" slot.
//
// The headers slot is intended for the small JSON blob that replaces
// the per-field encrypted address columns in Phase B3:
//
//	{"From":["Alice <alice@example.com>"], "To":["bob@bmail.ag"], ...}
//
// Pass `nil` for headers to fall back to the legacy two-slot encoding.
func EncryptMessageWithHeaders(recipientPub *ecdh.PublicKey, subject, body, headers []byte) (*EncryptedMessage, error) {
	messageKey, err := secureKey(32)
	if err != nil {
		return nil, fmt.Errorf("generate message key: %w", err)
	}
	defer ZeroBytes(messageKey)

	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	sharedSecret, err := ephemeral.ECDH(recipientPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}
	defer ZeroBytes(sharedSecret)

	ephPubBytes := ephemeral.PublicKey().Bytes()
	derivedKey, err := deriveKey(sharedSecret, ephPubBytes, "message-key-wrap")
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(derivedKey)

	encryptedMessageKey, err := sealXChaCha20(derivedKey, messageKey, ephPubBytes)
	if err != nil {
		return nil, fmt.Errorf("encrypt message key: %w", err)
	}

	encryptedBody, err := sealXChaCha20(messageKey, body, []byte("body"))
	if err != nil {
		return nil, fmt.Errorf("encrypt body: %w", err)
	}

	encryptedSubject, err := sealXChaCha20(messageKey, subject, []byte("subject"))
	if err != nil {
		return nil, fmt.Errorf("encrypt subject: %w", err)
	}

	out := &EncryptedMessage{
		EphemeralPubkey:     ephPubBytes,
		EncryptedMessageKey: encryptedMessageKey,
		EncryptedBody:       encryptedBody,
		EncryptedSubject:    encryptedSubject,
	}
	if headers != nil {
		encryptedHeaders, err := sealXChaCha20(messageKey, headers, []byte("headers"))
		if err != nil {
			return nil, fmt.Errorf("encrypt headers: %w", err)
		}
		out.EncryptedHeaders = encryptedHeaders
	}
	return out, nil
}

// DecryptRawMessage decrypts a raw message blob that may be single-block or chunked.
// It first unwraps the message key from the envelope, then decrypts the body
// using the format specified. If format is empty, assumes single-block (legacy).
// Also decrypts metadata if present.
func DecryptRawMessage(recipientPriv *ecdh.PrivateKey, msg *EncryptedMessage, format string, encryptedMeta []byte) (body, meta []byte, err error) {
	if len(msg.EphemeralPubkey) != 32 {
		return nil, nil, fmt.Errorf("invalid ephemeral public key length: %d", len(msg.EphemeralPubkey))
	}
	ephemeralPub, err := ecdh.X25519().NewPublicKey(msg.EphemeralPubkey)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ephemeral public key: %w", err)
	}

	sharedSecret, err := recipientPriv.ECDH(ephemeralPub)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDH: %w", err)
	}
	defer ZeroBytes(sharedSecret)

	derivedKey, err := deriveKey(sharedSecret, msg.EphemeralPubkey, "message-key-wrap")
	if err != nil {
		return nil, nil, err
	}
	defer ZeroBytes(derivedKey)

	messageKey, err := openXChaCha20(derivedKey, msg.EncryptedMessageKey, msg.EphemeralPubkey)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt message key: %w", err)
	}
	defer ZeroBytes(messageKey)

	// Decrypt body based on format.
	chunked, chunkSize := ParseRawBlobFormat(format)
	if chunked {
		body, err = DecryptChunked(messageKey, msg.EncryptedBody, chunkSize)
	} else {
		body, err = openXChaCha20(messageKey, msg.EncryptedBody, []byte("body"))
	}
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt body: %w", err)
	}

	// Decrypt metadata if present.
	if len(encryptedMeta) > 0 {
		meta, err = openXChaCha20(messageKey, encryptedMeta, []byte("raw-meta"))
		if err != nil {
			// Non-fatal: metadata is optional.
			meta = nil
		}
	}

	return body, meta, nil
}

// DecryptMetaOnly decrypts only the encrypted metadata without requiring
// the full message body. Used to extract headers and MIME structure from
// encrypted_raw_meta without downloading/decrypting the body blob.
func DecryptMetaOnly(recipientPriv *ecdh.PrivateKey, ephemeralPubkey, encryptedMessageKey, encryptedMeta []byte) ([]byte, error) {
	if len(ephemeralPubkey) != 32 {
		return nil, fmt.Errorf("invalid ephemeral public key length: %d", len(ephemeralPubkey))
	}
	ephPub, err := ecdh.X25519().NewPublicKey(ephemeralPubkey)
	if err != nil {
		return nil, fmt.Errorf("parse ephemeral public key: %w", err)
	}

	sharedSecret, err := recipientPriv.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}
	defer ZeroBytes(sharedSecret)

	derivedKey, err := deriveKey(sharedSecret, ephemeralPubkey, "message-key-wrap")
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(derivedKey)

	messageKey, err := openXChaCha20(derivedKey, encryptedMessageKey, ephemeralPubkey)
	if err != nil {
		return nil, fmt.Errorf("decrypt message key: %w", err)
	}
	defer ZeroBytes(messageKey)

	meta, err := openXChaCha20(messageKey, encryptedMeta, []byte("raw-meta"))
	if err != nil {
		return nil, fmt.Errorf("decrypt meta: %w", err)
	}
	return meta, nil
}

// RewrapMessageKey unwraps an attachment key (AK) encrypted for one recipient
// and re-wraps it for a different recipient. This allows a single encrypted
// blob to be shared across recipients — each gets their own small key wrap.
//
// Parameters:
//   - originalEphPubBytes: the ephemeral public key from the original encryption
//   - originalEncMsgKey: the wrapped AK (nonce || ciphertext) from the original encryption
//   - senderPriv: the sender's X25519 private key (used to unwrap the original AK)
//   - recipientPub: the new recipient's X25519 public key (used to re-wrap the AK)
//
// Returns: newEphPub (32 bytes), newEncMsgKey (nonce || ciphertext), or error.
func RewrapMessageKey(
	originalEphPubBytes, originalEncMsgKey []byte,
	senderPriv *ecdh.PrivateKey,
	recipientPub *ecdh.PublicKey,
) (newEphPub, newEncMsgKey []byte, err error) {
	if len(originalEphPubBytes) != 32 {
		return nil, nil, fmt.Errorf("invalid ephemeral public key length: %d (expected 32)", len(originalEphPubBytes))
	}

	// 1. Reconstruct the original ephemeral public key.
	originalEphPub, err := ecdh.X25519().NewPublicKey(originalEphPubBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse original ephemeral public key: %w", err)
	}

	// 2. ECDH(senderPriv, originalEphPub) → original shared secret.
	sharedSecret, err := senderPriv.ECDH(originalEphPub)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDH (unwrap): %w", err)
	}
	defer ZeroBytes(sharedSecret)

	// 3. Derive the original wrapping key.
	derivedKey, err := deriveKey(sharedSecret, originalEphPubBytes, "message-key-wrap")
	if err != nil {
		return nil, nil, err
	}
	defer ZeroBytes(derivedKey)

	// 4. Unwrap the AK.
	ak, err := openXChaCha20(derivedKey, originalEncMsgKey, originalEphPubBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("unwrap attachment key: %w", err)
	}
	defer ZeroBytes(ak)

	// 5. Generate new ephemeral keypair for the recipient.
	newEphKP, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate new ephemeral key: %w", err)
	}

	// 6. ECDH(newEphPriv, recipientPub) → new shared secret.
	newSharedSecret, err := newEphKP.ECDH(recipientPub)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDH (rewrap): %w", err)
	}
	defer ZeroBytes(newSharedSecret)

	// 7. Derive new wrapping key.
	newEphPubBytes := newEphKP.PublicKey().Bytes()
	newDerivedKey, err := deriveKey(newSharedSecret, newEphPubBytes, "message-key-wrap")
	if err != nil {
		return nil, nil, err
	}
	defer ZeroBytes(newDerivedKey)

	// 8. Re-wrap the AK for the new recipient.
	newEncMsgKey, err = sealXChaCha20(newDerivedKey, ak, newEphPubBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("rewrap attachment key: %w", err)
	}

	return newEphPubBytes, newEncMsgKey, nil
}

// DecryptSubject decrypts only the subject field of an encrypted message,
// without requiring the encrypted body. Used for message list subject previews.
func DecryptSubject(recipientPriv *ecdh.PrivateKey, ephemeralPubkey, encryptedMessageKey, encryptedSubject []byte) ([]byte, error) {
	if len(ephemeralPubkey) != 32 {
		return nil, fmt.Errorf("invalid ephemeral public key length: %d (expected 32)", len(ephemeralPubkey))
	}
	ephemeralPub, err := ecdh.X25519().NewPublicKey(ephemeralPubkey)
	if err != nil {
		return nil, fmt.Errorf("parse ephemeral public key: %w", err)
	}
	sharedSecret, err := recipientPriv.ECDH(ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}
	defer ZeroBytes(sharedSecret)
	derivedKey, err := deriveKey(sharedSecret, ephemeralPubkey, "message-key-wrap")
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(derivedKey)
	messageKey, err := openXChaCha20(derivedKey, encryptedMessageKey, ephemeralPubkey)
	if err != nil {
		return nil, fmt.Errorf("decrypt message key: %w", err)
	}
	defer ZeroBytes(messageKey)
	subject, err := openXChaCha20(messageKey, encryptedSubject, []byte("subject"))
	if err != nil {
		return nil, fmt.Errorf("decrypt subject: %w", err)
	}
	return subject, nil
}

// ---------------------------------------------------------------------------
// Hybrid-aware functions: X25519 + ML-KEM-768
// ---------------------------------------------------------------------------

// EncryptMessageHybrid encrypts a message using hybrid X25519 + ML-KEM-768
// when kemEK is non-nil, or classical X25519 when kemEK is nil.
func EncryptMessageHybrid(recipientPub *ecdh.PublicKey, kemEK *mlkem.EncapsulationKey768, subject, body []byte) (*EncryptedMessage, error) {
	messageKey, err := secureKey(32)
	if err != nil {
		return nil, fmt.Errorf("generate message key: %w", err)
	}
	defer ZeroBytes(messageKey)

	envelopeKey, encryptedMessageKey, err := wrapEnvelope(recipientPub, kemEK, messageKey)
	if err != nil {
		return nil, err
	}

	encryptedBody, err := sealXChaCha20(messageKey, body, []byte("body"))
	if err != nil {
		return nil, fmt.Errorf("encrypt body: %w", err)
	}

	encryptedSubject, err := sealXChaCha20(messageKey, subject, []byte("subject"))
	if err != nil {
		return nil, fmt.Errorf("encrypt subject: %w", err)
	}

	return &EncryptedMessage{
		EphemeralPubkey:     envelopeKey,
		EncryptedMessageKey: encryptedMessageKey,
		EncryptedBody:       encryptedBody,
		EncryptedSubject:    encryptedSubject,
	}, nil
}

// EncryptMessageWithHeadersHybrid is the hybrid variant of EncryptMessageWithHeaders.
func EncryptMessageWithHeadersHybrid(recipientPub *ecdh.PublicKey, kemEK *mlkem.EncapsulationKey768, subject, body, headers []byte) (*EncryptedMessage, error) {
	messageKey, err := secureKey(32)
	if err != nil {
		return nil, fmt.Errorf("generate message key: %w", err)
	}
	defer ZeroBytes(messageKey)

	envelopeKey, encryptedMessageKey, err := wrapEnvelope(recipientPub, kemEK, messageKey)
	if err != nil {
		return nil, err
	}

	encryptedBody, err := sealXChaCha20(messageKey, body, []byte("body"))
	if err != nil {
		return nil, fmt.Errorf("encrypt body: %w", err)
	}

	encryptedSubject, err := sealXChaCha20(messageKey, subject, []byte("subject"))
	if err != nil {
		return nil, fmt.Errorf("encrypt subject: %w", err)
	}

	out := &EncryptedMessage{
		EphemeralPubkey:     envelopeKey,
		EncryptedMessageKey: encryptedMessageKey,
		EncryptedBody:       encryptedBody,
		EncryptedSubject:    encryptedSubject,
	}
	if headers != nil {
		encryptedHeaders, err := sealXChaCha20(messageKey, headers, []byte("headers"))
		if err != nil {
			return nil, fmt.Errorf("encrypt headers: %w", err)
		}
		out.EncryptedHeaders = encryptedHeaders
	}
	return out, nil
}

// DecryptMessageAuto decrypts a message, auto-detecting classical vs hybrid
// from the envelope key length. If the envelope is hybrid, kemDK must be non-nil.
func DecryptMessageAuto(recipientPriv *ecdh.PrivateKey, kemDK *mlkem.DecapsulationKey768, msg *EncryptedMessage) (subject, body []byte, err error) {
	messageKey, err := unwrapEnvelope(recipientPriv, kemDK, msg.EphemeralPubkey, msg.EncryptedMessageKey)
	if err != nil {
		return nil, nil, err
	}
	defer ZeroBytes(messageKey)

	body, err = openXChaCha20(messageKey, msg.EncryptedBody, []byte("body"))
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt body: %w", err)
	}

	if len(msg.EncryptedSubject) > 0 {
		subject, err = openXChaCha20(messageKey, msg.EncryptedSubject, []byte("subject"))
		if err != nil {
			return nil, nil, fmt.Errorf("decrypt subject: %w", err)
		}
	}

	return subject, body, nil
}

// DecryptSubjectOnlyAuto is the hybrid-aware variant of DecryptSubjectOnly.
func DecryptSubjectOnlyAuto(recipientPriv *ecdh.PrivateKey, kemDK *mlkem.DecapsulationKey768, envelopeKey, encryptedMessageKey, encryptedSubject []byte) ([]byte, error) {
	messageKey, err := unwrapEnvelope(recipientPriv, kemDK, envelopeKey, encryptedMessageKey)
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(messageKey)

	subject, err := openXChaCha20(messageKey, encryptedSubject, []byte("subject"))
	if err != nil {
		return nil, fmt.Errorf("decrypt subject: %w", err)
	}
	return subject, nil
}

// DecryptHeadersAuto is the hybrid-aware variant of DecryptHeaders.
func DecryptHeadersAuto(recipientPriv *ecdh.PrivateKey, kemDK *mlkem.DecapsulationKey768, envelopeKey, encryptedMessageKey, encryptedHeaders []byte) ([]byte, error) {
	if len(encryptedHeaders) == 0 {
		return nil, fmt.Errorf("encrypted headers are empty")
	}
	messageKey, err := unwrapEnvelope(recipientPriv, kemDK, envelopeKey, encryptedMessageKey)
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(messageKey)

	headers, err := openXChaCha20(messageKey, encryptedHeaders, []byte("headers"))
	if err != nil {
		return nil, fmt.Errorf("decrypt headers: %w", err)
	}
	return headers, nil
}

// DecryptMetaOnlyAuto is the hybrid-aware variant of DecryptMetaOnly.
func DecryptMetaOnlyAuto(recipientPriv *ecdh.PrivateKey, kemDK *mlkem.DecapsulationKey768, envelopeKey, encryptedMessageKey, encryptedMeta []byte) ([]byte, error) {
	messageKey, err := unwrapEnvelope(recipientPriv, kemDK, envelopeKey, encryptedMessageKey)
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(messageKey)

	meta, err := openXChaCha20(messageKey, encryptedMeta, []byte("raw-meta"))
	if err != nil {
		return nil, fmt.Errorf("decrypt meta: %w", err)
	}
	return meta, nil
}

// DecryptRawMessageAuto is the hybrid-aware variant of DecryptRawMessage.
func DecryptRawMessageAuto(recipientPriv *ecdh.PrivateKey, kemDK *mlkem.DecapsulationKey768, msg *EncryptedMessage, format string, encryptedMeta []byte) (body, meta []byte, err error) {
	messageKey, err := unwrapEnvelope(recipientPriv, kemDK, msg.EphemeralPubkey, msg.EncryptedMessageKey)
	if err != nil {
		return nil, nil, err
	}
	defer ZeroBytes(messageKey)

	chunked, chunkSize := ParseRawBlobFormat(format)
	if chunked {
		body, err = DecryptChunked(messageKey, msg.EncryptedBody, chunkSize)
	} else {
		body, err = openXChaCha20(messageKey, msg.EncryptedBody, []byte("body"))
	}
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt body: %w", err)
	}

	if len(encryptedMeta) > 0 {
		meta, err = openXChaCha20(messageKey, encryptedMeta, []byte("raw-meta"))
		if err != nil {
			meta = nil
		}
	}

	return body, meta, nil
}

// RewrapMessageKeyHybrid unwraps a message key from an envelope (classical or
// hybrid) and re-wraps it for a new recipient, optionally using hybrid.
func RewrapMessageKeyHybrid(
	originalEnvelopeKey, originalEncMsgKey []byte,
	senderPriv *ecdh.PrivateKey,
	senderKEMDK *mlkem.DecapsulationKey768,
	recipientPub *ecdh.PublicKey,
	recipientKEMEK *mlkem.EncapsulationKey768,
) (newEnvelopeKey, newEncMsgKey []byte, err error) {
	// Unwrap using auto-detect (handles both classical and hybrid originals).
	ak, err := unwrapEnvelope(senderPriv, senderKEMDK, originalEnvelopeKey, originalEncMsgKey)
	if err != nil {
		return nil, nil, fmt.Errorf("unwrap: %w", err)
	}
	defer ZeroBytes(ak)

	// Re-wrap for the new recipient (hybrid if they have a KEM key).
	newEnvelopeKey, newEncMsgKey, err = wrapEnvelope(recipientPub, recipientKEMEK, ak)
	if err != nil {
		return nil, nil, fmt.Errorf("rewrap: %w", err)
	}
	return newEnvelopeKey, newEncMsgKey, nil
}

// EncryptRawMessageWithMetaHybrid is the hybrid variant of EncryptRawMessageWithMeta.
func EncryptRawMessageWithMetaHybrid(recipientPub *ecdh.PublicKey, kemEK *mlkem.EncapsulationKey768, rawMessage, metadata []byte, chunkSize int) (*EncryptedRawMessage, error) {
	messageKey, err := secureKey(32)
	if err != nil {
		return nil, fmt.Errorf("generate message key: %w", err)
	}
	defer ZeroBytes(messageKey)

	envelopeKey, encryptedMessageKey, err := wrapEnvelope(recipientPub, kemEK, messageKey)
	if err != nil {
		return nil, err
	}

	var encryptedBody []byte
	if chunkSize > 0 {
		encryptedBody, err = EncryptChunked(messageKey, rawMessage, chunkSize)
		if err != nil {
			return nil, fmt.Errorf("encrypt body (chunked): %w", err)
		}
	} else {
		encryptedBody, err = sealXChaCha20(messageKey, rawMessage, []byte("body"))
		if err != nil {
			return nil, fmt.Errorf("encrypt body: %w", err)
		}
	}

	encryptedMeta, err := sealXChaCha20(messageKey, metadata, []byte("raw-meta"))
	if err != nil {
		return nil, fmt.Errorf("encrypt metadata: %w", err)
	}

	return &EncryptedRawMessage{
		EncryptedMessage: EncryptedMessage{
			EphemeralPubkey:     envelopeKey,
			EncryptedMessageKey: encryptedMessageKey,
			EncryptedBody:       encryptedBody,
		},
		EncryptedMeta: encryptedMeta,
	}, nil
}

// EncryptMessageChunkedBody is like EncryptMessage but uses chunked encryption
// for the body field. The subject and message key wrapping use single-block.
// Used for raw message blobs that benefit from range-based decryption.
func EncryptMessageChunkedBody(recipientPub *ecdh.PublicKey, subject, body []byte, chunkSize int) (*EncryptedMessage, error) {
	messageKey, err := secureKey(32)
	if err != nil {
		return nil, fmt.Errorf("generate message key: %w", err)
	}
	defer ZeroBytes(messageKey)

	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	sharedSecret, err := ephemeral.ECDH(recipientPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}
	defer ZeroBytes(sharedSecret)

	ephPubBytes := ephemeral.PublicKey().Bytes()
	derivedKey, err := deriveKey(sharedSecret, ephPubBytes, "message-key-wrap")
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(derivedKey)

	encryptedMessageKey, err := sealXChaCha20(derivedKey, messageKey, ephPubBytes)
	if err != nil {
		return nil, fmt.Errorf("encrypt message key: %w", err)
	}

	// Body: chunked encryption for range access.
	encryptedBody, err := EncryptChunked(messageKey, body, chunkSize)
	if err != nil {
		return nil, fmt.Errorf("encrypt body (chunked): %w", err)
	}

	// Subject: single-block (always small).
	encryptedSubject, err := sealXChaCha20(messageKey, subject, []byte("subject"))
	if err != nil {
		return nil, fmt.Errorf("encrypt subject: %w", err)
	}

	return &EncryptedMessage{
		EphemeralPubkey:     ephPubBytes,
		EncryptedMessageKey: encryptedMessageKey,
		EncryptedBody:       encryptedBody,
		EncryptedSubject:    encryptedSubject,
	}, nil
}

// EncryptedRawMessage holds the chunked body + separately encrypted metadata.
type EncryptedRawMessage struct {
	EncryptedMessage                      // embedded: EphemeralPubkey, EncryptedMessageKey, EncryptedBody (chunked), EncryptedSubject
	EncryptedMeta    []byte               // metadata encrypted with the same message key (single block)
}

// EncryptRawMessageWithMeta encrypts a raw message body as chunked and also
// encrypts metadata (JSON) with the same message key as a single block.
// The metadata can be decrypted independently using the same message key.
func EncryptRawMessageWithMeta(recipientPub *ecdh.PublicKey, rawMessage, metadata []byte, chunkSize int) (*EncryptedRawMessage, error) {
	messageKey, err := secureKey(32)
	if err != nil {
		return nil, fmt.Errorf("generate message key: %w", err)
	}
	defer ZeroBytes(messageKey)

	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	sharedSecret, err := ephemeral.ECDH(recipientPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}
	defer ZeroBytes(sharedSecret)

	ephPubBytes := ephemeral.PublicKey().Bytes()
	derivedKey, err := deriveKey(sharedSecret, ephPubBytes, "message-key-wrap")
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(derivedKey)

	encryptedMessageKey, err := sealXChaCha20(derivedKey, messageKey, ephPubBytes)
	if err != nil {
		return nil, fmt.Errorf("encrypt message key: %w", err)
	}

	// Body: chunked or single-block depending on chunkSize.
	var encryptedBody []byte
	if chunkSize > 0 {
		encryptedBody, err = EncryptChunked(messageKey, rawMessage, chunkSize)
		if err != nil {
			return nil, fmt.Errorf("encrypt body (chunked): %w", err)
		}
	} else {
		encryptedBody, err = sealXChaCha20(messageKey, rawMessage, []byte("body"))
		if err != nil {
			return nil, fmt.Errorf("encrypt body: %w", err)
		}
	}

	// Metadata: single-block encryption with AAD "raw-meta".
	encryptedMeta, err := sealXChaCha20(messageKey, metadata, []byte("raw-meta"))
	if err != nil {
		return nil, fmt.Errorf("encrypt metadata: %w", err)
	}

	return &EncryptedRawMessage{
		EncryptedMessage: EncryptedMessage{
			EphemeralPubkey:     ephPubBytes,
			EncryptedMessageKey: encryptedMessageKey,
			EncryptedBody:       encryptedBody,
			EncryptedSubject:    nil, // raw messages don't have a separate subject
		},
		EncryptedMeta: encryptedMeta,
	}, nil
}

// --- Chunked encryption for raw message blobs ---

const (
	// DefaultChunkSize is the plaintext chunk size for chunked encryption (64KB).
	DefaultChunkSize = 65536
	// ChunkTagSize is the Poly1305 authentication tag size per chunk.
	ChunkTagSize = 16
	// RawBlobFormatSingle is the format string for single-block encryption.
	RawBlobFormatSingle = "XChaCha20-Poly1305"
)

// RawBlobFormatChunked returns the format string for chunked encryption with the given chunk size.
func RawBlobFormatChunked(chunkSize int) string {
	return fmt.Sprintf("XChaCha20-Poly1305-Chunked(%d)", chunkSize)
}

// ParseRawBlobFormat parses a raw_blob_format string.
// Returns whether it's chunked and the chunk size (0 for single-block).
func ParseRawBlobFormat(format string) (chunked bool, chunkSize int) {
	var cs int
	if n, _ := fmt.Sscanf(format, "XChaCha20-Poly1305-Chunked(%d)", &cs); n == 1 && cs > 0 {
		return true, cs
	}
	return false, 0
}

// deriveChunkNonce derives a 24-byte nonce for a specific chunk index using HKDF.
func deriveChunkNonce(messageKey []byte, chunkIndex int) ([]byte, error) {
	var info [8]byte
	binary.BigEndian.PutUint64(info[:], uint64(chunkIndex))
	hkdfReader := hkdf.New(sha256.New, messageKey, []byte("chunk-nonce"), info[:])
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(hkdfReader, nonce); err != nil {
		return nil, fmt.Errorf("derive chunk nonce: %w", err)
	}
	return nonce, nil
}

// chunkAAD returns the AAD for a specific chunk index.
func chunkAAD(chunkIndex int) []byte {
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], uint64(chunkIndex))
	aad := make([]byte, 0, len("raw:chunk:")+8)
	aad = append(aad, "raw:chunk:"...)
	aad = append(aad, idx[:]...)
	return aad
}

// EncryptChunked encrypts plaintext as concatenated XChaCha20-Poly1305 chunks.
// Each chunk uses a nonce derived from the message key and chunk index.
// The output contains no headers or identifying bytes — just ciphertext+tag per chunk.
func EncryptChunked(messageKey, plaintext []byte, chunkSize int) ([]byte, error) {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	aead, err := chacha20poly1305.NewX(messageKey)
	if err != nil {
		return nil, fmt.Errorf("create AEAD: %w", err)
	}

	numChunks := (len(plaintext) + chunkSize - 1) / chunkSize
	if numChunks == 0 {
		numChunks = 1 // at least one chunk for empty plaintext
	}

	// Pre-allocate output: each chunk is plaintext_len + 16 (tag)
	out := make([]byte, 0, len(plaintext)+numChunks*ChunkTagSize)

	for i := 0; i < numChunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(plaintext) {
			end = len(plaintext)
		}
		chunk := plaintext[start:end]

		nonce, err := deriveChunkNonce(messageKey, i)
		if err != nil {
			return nil, err
		}
		aad := chunkAAD(i)
		sealed := aead.Seal(nil, nonce, chunk, aad)
		out = append(out, sealed...)
	}

	return out, nil
}

// DecryptChunked decrypts a full chunked blob.
func DecryptChunked(messageKey, blob []byte, chunkSize int) ([]byte, error) {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	aead, err := chacha20poly1305.NewX(messageKey)
	if err != nil {
		return nil, fmt.Errorf("create AEAD: %w", err)
	}

	storedChunkSize := chunkSize + ChunkTagSize
	var plaintext []byte

	for i := 0; ; i++ {
		offset := i * storedChunkSize
		if offset >= len(blob) {
			break
		}
		end := offset + storedChunkSize
		if end > len(blob) {
			end = len(blob)
		}
		chunkData := blob[offset:end]

		nonce, err := deriveChunkNonce(messageKey, i)
		if err != nil {
			return nil, err
		}
		aad := chunkAAD(i)
		decrypted, err := aead.Open(nil, nonce, chunkData, aad)
		if err != nil {
			return nil, fmt.Errorf("decrypt chunk %d: %w", i, err)
		}
		plaintext = append(plaintext, decrypted...)
	}

	return plaintext, nil
}

// DecryptChunk decrypts a single chunk by index.
// chunkData is the raw bytes for that chunk (ciphertext + tag, no nonce).
func DecryptChunk(messageKey []byte, chunkIndex int, chunkData []byte, chunkSize int) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(messageKey)
	if err != nil {
		return nil, fmt.Errorf("create AEAD: %w", err)
	}
	nonce, err := deriveChunkNonce(messageKey, chunkIndex)
	if err != nil {
		return nil, err
	}
	aad := chunkAAD(chunkIndex)
	return aead.Open(nil, nonce, chunkData, aad)
}
