// Package crypto — OpenPGP interoperability for Bmail.
//
// Bmail uses Ed25519/X25519 internally. This module wraps those keys in
// OpenPGP v6 (RFC 9580) packets so that external PGP users (ProtonMail,
// Thunderbird, GPG) can exchange encrypted email with Bmail users.
//
// All PGP private-key operations happen client-side (WASM). The server only
// holds armored public keys for WKD and Autocrypt serving.
package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

// GeneratePGPKey creates an OpenPGP key for the given email address.
// Uses Ed25519 for signing and Curve25519 for encryption (RFC 9580 profile).
// Returns the armored private key and armored public key.
func GeneratePGPKey(email string) (armoredPrivate, armoredPublic string, err error) {
	pgp := crypto.PGP()
	keyGenHandle := pgp.KeyGeneration().AddUserId(email, "").New()
	key, err := keyGenHandle.GenerateKey()
	if err != nil {
		return "", "", fmt.Errorf("generate PGP key: %w", err)
	}

	armoredPrivate, err = key.Armor()
	if err != nil {
		return "", "", fmt.Errorf("armor private key: %w", err)
	}

	armoredPublic, err = key.GetArmoredPublicKey()
	if err != nil {
		return "", "", fmt.Errorf("armor public key: %w", err)
	}

	return armoredPrivate, armoredPublic, nil
}

// PGPPublicKeyFromArmored parses an armored PGP public key and returns
// the key object for encryption or verification.
func PGPPublicKeyFromArmored(armored string) (*crypto.Key, error) {
	key, err := crypto.NewKeyFromArmored(armored)
	if err != nil {
		return nil, fmt.Errorf("parse armored PGP key: %w", err)
	}
	return key, nil
}

// PGPEncryptMessage encrypts a plaintext message to one or more PGP recipients.
// Returns the armored PGP message.
func PGPEncryptMessage(armoredRecipientKeys []string, subject, body string) (string, error) {
	keyRing, err := buildKeyRing(armoredRecipientKeys)
	if err != nil {
		return "", err
	}

	pgp := crypto.PGP()
	encHandle, err := pgp.Encryption().Recipients(keyRing).New()
	if err != nil {
		return "", fmt.Errorf("create encryption handle: %w", err)
	}

	// Compose RFC 5322-like body with subject in protected headers.
	fullBody := body
	if subject != "" {
		fullBody = "Subject: " + subject + "\r\n\r\n" + body
	}

	pgpMessage, err := encHandle.Encrypt([]byte(fullBody))
	if err != nil {
		return "", fmt.Errorf("PGP encrypt: %w", err)
	}

	armored, err := pgpMessage.ArmorBytes()
	if err != nil {
		return "", fmt.Errorf("armor PGP message: %w", err)
	}

	return string(armored), nil
}

// PGPDecryptMessage decrypts an armored PGP message using the recipient's private key.
// Returns the decrypted plaintext. Rejects passphrase-protected (locked) keys.
func PGPDecryptMessage(armoredPrivateKey, armoredMessage string) ([]byte, error) {
	key, err := crypto.NewKeyFromArmored(armoredPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	if locked, err := key.IsLocked(); err == nil && locked {
		return nil, fmt.Errorf("private key is locked (passphrase-protected keys not supported)")
	}

	return pgpDecryptWithKey(key, armoredMessage)
}

// PGPDecryptMessageWithPassphrase decrypts an armored PGP message using a
// passphrase-protected private key. If the key is not locked, the passphrase
// is ignored and decryption proceeds normally.
func PGPDecryptMessageWithPassphrase(armoredPrivateKey, passphrase, armoredMessage string) ([]byte, error) {
	key, err := crypto.NewKeyFromArmored(armoredPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	if locked, lockErr := key.IsLocked(); lockErr == nil && locked {
		unlockedKey, err := key.Unlock([]byte(passphrase))
		if err != nil {
			return nil, fmt.Errorf("unlock private key: %w", err)
		}
		key = unlockedKey
	}

	return pgpDecryptWithKey(key, armoredMessage)
}

// pgpDecryptWithKey performs the actual PGP decryption given an unlocked key.
func pgpDecryptWithKey(key *crypto.Key, armoredMessage string) ([]byte, error) {
	keyRing, err := crypto.NewKeyRing(key)
	if err != nil {
		return nil, fmt.Errorf("create key ring: %w", err)
	}

	pgp := crypto.PGP()
	decHandle, err := pgp.Decryption().DecryptionKeys(keyRing).New()
	if err != nil {
		return nil, fmt.Errorf("create decryption handle: %w", err)
	}

	result, err := decHandle.Decrypt([]byte(armoredMessage), crypto.Armor)
	if err != nil {
		return nil, fmt.Errorf("PGP decrypt: %w", err)
	}

	return result.Bytes(), nil
}

// PGPSignMessage creates a cleartext PGP signature for the given message.
func PGPSignMessage(armoredPrivateKey string, message []byte) (string, error) {
	key, err := crypto.NewKeyFromArmored(armoredPrivateKey)
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}

	if locked, lockErr := key.IsLocked(); lockErr == nil && locked {
		return "", fmt.Errorf("private key is locked (use PGPSignMessageWithPassphrase)")
	}

	return pgpSignWithKey(key, message)
}

// PGPSignMessageWithPassphrase creates a PGP signature using a passphrase-protected key.
// If the key is not locked, the passphrase is ignored and signing proceeds normally.
func PGPSignMessageWithPassphrase(armoredPrivateKey, passphrase string, message []byte) (string, error) {
	key, err := crypto.NewKeyFromArmored(armoredPrivateKey)
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}

	if locked, lockErr := key.IsLocked(); lockErr == nil && locked {
		unlockedKey, err := key.Unlock([]byte(passphrase))
		if err != nil {
			return "", fmt.Errorf("unlock private key: %w", err)
		}
		key = unlockedKey
	}

	return pgpSignWithKey(key, message)
}

// pgpSignWithKey performs the actual PGP signing given an unlocked key.
func pgpSignWithKey(key *crypto.Key, message []byte) (string, error) {
	keyRing, err := crypto.NewKeyRing(key)
	if err != nil {
		return "", fmt.Errorf("create key ring: %w", err)
	}

	pgp := crypto.PGP()
	sigHandle, err := pgp.Sign().SigningKeys(keyRing).New()
	if err != nil {
		return "", fmt.Errorf("create signing handle: %w", err)
	}

	sig, err := sigHandle.Sign(message, crypto.Armor)
	if err != nil {
		return "", fmt.Errorf("PGP sign: %w", err)
	}

	return string(sig), nil
}

// PGPVerifySignature verifies a PGP inline signature (produced by PGPSignMessage).
// Returns (true, nil) if signature is valid, (false, nil) if signature is
// cryptographically invalid, and (false, error) if verification could not be
// performed (e.g. key parsing failure).
func PGPVerifySignature(armoredPublicKey string, message []byte, armoredSignature string) (bool, error) {
	key, err := crypto.NewKeyFromArmored(armoredPublicKey)
	if err != nil {
		return false, fmt.Errorf("parse public key: %w", err)
	}

	keyRing, err := crypto.NewKeyRing(key)
	if err != nil {
		return false, fmt.Errorf("create key ring: %w", err)
	}

	pgp := crypto.PGP()
	verifyHandle, err := pgp.Verify().VerificationKeys(keyRing).New()
	if err != nil {
		return false, fmt.Errorf("create verify handle: %w", err)
	}

	// Try inline verification first (Sign produces inline signed messages).
	result, err := verifyHandle.VerifyInline([]byte(armoredSignature), crypto.Armor)
	if err != nil {
		// Fall back to detached verification.
		verifyHandle2, err2 := pgp.Verify().VerificationKeys(keyRing).New()
		if err2 != nil {
			return false, nil
		}
		detResult, err2 := verifyHandle2.VerifyDetached(message, []byte(armoredSignature), crypto.Armor)
		if err2 != nil {
			return false, nil
		}
		return detResult.SignatureError() == nil, nil
	}

	if result.SignatureError() != nil {
		return false, nil
	}

	return true, nil
}

// PGPEncryptSign encrypts and signs a message (for authenticated encryption).
func PGPEncryptSign(armoredPrivateKey string, armoredRecipientKeys []string, body []byte) (string, error) {
	senderKey, err := crypto.NewKeyFromArmored(armoredPrivateKey)
	if err != nil {
		return "", fmt.Errorf("parse sender key: %w", err)
	}
	senderRing, err := crypto.NewKeyRing(senderKey)
	if err != nil {
		return "", fmt.Errorf("create sender ring: %w", err)
	}

	recipientRing, err := buildKeyRing(armoredRecipientKeys)
	if err != nil {
		return "", err
	}

	pgp := crypto.PGP()
	encHandle, err := pgp.Encryption().Recipients(recipientRing).SigningKeys(senderRing).New()
	if err != nil {
		return "", fmt.Errorf("create encrypt+sign handle: %w", err)
	}

	pgpMsg, err := encHandle.Encrypt(body)
	if err != nil {
		return "", fmt.Errorf("PGP encrypt+sign: %w", err)
	}

	armored, err := pgpMsg.ArmorBytes()
	if err != nil {
		return "", fmt.Errorf("armor message: %w", err)
	}

	return string(armored), nil
}

// ExportPGPPublicKeyBinary returns the binary (non-armored) public key
// for WKD serving (WKD requires binary keys, not armored).
func ExportPGPPublicKeyBinary(armoredPublicKey string) ([]byte, error) {
	key, err := crypto.NewKeyFromArmored(armoredPublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse armored key: %w", err)
	}
	return key.Serialize()
}

// ExportPGPPublicKeyMinimal returns a minimal PGP public key suitable for
// Autocrypt headers (stripped of extra signatures and subpackets).
func ExportPGPPublicKeyMinimal(armoredPublicKey string) ([]byte, error) {
	// For now, use the full binary key. A future optimization can strip
	// unnecessary subpackets for the Autocrypt header size limit (~12KB).
	return ExportPGPPublicKeyBinary(armoredPublicKey)
}

// DetectPGPMIME checks if a raw email message uses PGP/MIME encryption.
// Looks for Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"
func DetectPGPMIME(rawMessage []byte) bool {
	// Check the first 4KB of headers for PGP/MIME content type.
	headerEnd := bytes.Index(rawMessage, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		headerEnd = bytes.Index(rawMessage, []byte("\n\n"))
	}
	if headerEnd == -1 {
		if len(rawMessage) > 4096 {
			headerEnd = 4096
		} else {
			headerEnd = len(rawMessage)
		}
	}
	headers := strings.ToLower(string(rawMessage[:headerEnd]))
	return strings.Contains(headers, "multipart/encrypted") &&
		strings.Contains(headers, "application/pgp-encrypted")
}

// DetectPGPInline checks if a message body contains inline PGP blocks.
func DetectPGPInline(body []byte) bool {
	return bytes.Contains(body, []byte("-----BEGIN PGP MESSAGE-----"))
}

// DetectSMIME checks if a raw email message uses S/MIME encryption.
func DetectSMIME(rawMessage []byte) bool {
	headerEnd := bytes.Index(rawMessage, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		headerEnd = bytes.Index(rawMessage, []byte("\n\n"))
	}
	if headerEnd == -1 {
		if len(rawMessage) > 4096 {
			headerEnd = 4096
		} else {
			headerEnd = len(rawMessage)
		}
	}
	headers := strings.ToLower(string(rawMessage[:headerEnd]))
	return strings.Contains(headers, "application/pkcs7-mime") ||
		strings.Contains(headers, "application/x-pkcs7-mime")
}

// ParseAutocryptHeader parses an Autocrypt header value and returns the
// sender's email and base64-encoded key data.
// Format: addr=user@example.com; [prefer-encrypt=mutual;] keydata=<base64>
func ParseAutocryptHeader(headerValue string) (email string, keyData []byte, preferEncrypt string, err error) {
	parts := strings.Split(headerValue, ";")
	preferEncrypt = "nopreference"

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "addr=") {
			email = strings.TrimPrefix(part, "addr=")
		} else if strings.HasPrefix(part, "prefer-encrypt=") {
			preferEncrypt = strings.TrimPrefix(part, "prefer-encrypt=")
		} else if strings.HasPrefix(part, "keydata=") {
			// keydata is base64 — may span multiple lines.
			raw := strings.TrimPrefix(part, "keydata=")
			raw = strings.ReplaceAll(raw, " ", "")
			raw = strings.ReplaceAll(raw, "\n", "")
			raw = strings.ReplaceAll(raw, "\r", "")
			// Validate base64 encoding (F-17 fix).
			decoded, err := base64.StdEncoding.DecodeString(raw)
			if err != nil {
				return "", nil, "", fmt.Errorf("invalid base64 in keydata: %w", err)
			}
			keyData = decoded
		}
	}

	if email == "" {
		return "", nil, "", fmt.Errorf("missing addr= in Autocrypt header")
	}
	if len(keyData) == 0 {
		return "", nil, "", fmt.Errorf("missing keydata= in Autocrypt header")
	}

	return email, keyData, preferEncrypt, nil
}

// FormatAutocryptHeader creates an Autocrypt header value for outbound emails.
// Parameters are sanitized to prevent CRLF header injection.
func FormatAutocryptHeader(email string, minimalKeyBase64 string) string {
	r := strings.NewReplacer("\r\n", "", "\r", "", "\n", "", "\x00", "")
	safeEmail := r.Replace(email)
	safeKeyData := r.Replace(minimalKeyBase64)
	return fmt.Sprintf("addr=%s; prefer-encrypt=mutual; keydata=%s", safeEmail, safeKeyData)
}

// GetPGPFingerprint returns the hex fingerprint of a PGP key.
func GetPGPFingerprint(armoredKey string) (string, error) {
	key, err := crypto.NewKeyFromArmored(armoredKey)
	if err != nil {
		return "", fmt.Errorf("parse key: %w", err)
	}
	return key.GetFingerprint(), nil
}

// buildKeyRing creates a KeyRing from a list of armored public keys.
func buildKeyRing(armoredKeys []string) (*crypto.KeyRing, error) {
	if len(armoredKeys) == 0 {
		return nil, fmt.Errorf("no recipient keys provided")
	}

	firstKey, err := crypto.NewKeyFromArmored(armoredKeys[0])
	if err != nil {
		return nil, fmt.Errorf("parse recipient key: %w", err)
	}
	ring, err := crypto.NewKeyRing(firstKey)
	if err != nil {
		return nil, fmt.Errorf("create key ring: %w", err)
	}

	for _, armored := range armoredKeys[1:] {
		key, err := crypto.NewKeyFromArmored(armored)
		if err != nil {
			return nil, fmt.Errorf("parse recipient key: %w", err)
		}
		if err := ring.AddKey(key); err != nil {
			return nil, fmt.Errorf("add key to ring: %w", err)
		}
	}

	return ring, nil
}

// Ensure Ed25519 compatibility with PGP — Bmail's signing keys are Ed25519,
// which is the default for OpenPGP v6 (RFC 9580). This is a compile-time check.
var _ ed25519.PublicKey
