//go:build js && wasm

package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"syscall/js"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/bmailag/bmail/internal/crypto"
)

// ── Attachment Encryption ────────────────────────────────────

// encryptAttachmentJS encrypts an attachment (file data + metadata) for a recipient's public key.
// Args: pubKeyB64 (base64 X25519 public key), dataB64 (base64 file data), metadataJSON (e.g. {"filename":"x","content_type":"y"})
// Returns: JSON { ephemeral_pubkey, encrypted_key, encrypted_data, encrypted_metadata }
func encryptAttachmentJS(args []js.Value) (interface{}, error) {
	if len(args) < 3 {
		return nil, fmt.Errorf("encryptAttachment requires 3+ args: pubKeyB64, dataB64, metadataJSON, [kemEKB64]")
	}
	pubKeyBytes, err := unb64(args[0].String())
	if err != nil {
		return nil, fmt.Errorf("decode pubKey: %w", err)
	}
	dataBytes, err := unb64(args[1].String())
	if err != nil {
		return nil, fmt.Errorf("decode data: %w", err)
	}
	metadataJSON := args[2].String()

	// Optional 4th arg: recipient's ML-KEM-768 encapsulation key for hybrid.
	kemEK, err := parseOptionalKEMEK(args, 3)
	if err != nil {
		return nil, err
	}

	pubKey, err := ecdh.X25519().NewPublicKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	em, err := crypto.EncryptMessageHybrid(pubKey, kemEK, []byte(metadataJSON), dataBytes)
	if err != nil {
		return nil, err
	}

	result := map[string]string{
		"ephemeral_pubkey":   b64(em.EphemeralPubkey),
		"encrypted_key":      b64(em.EncryptedMessageKey),
		"encrypted_data":     b64(em.EncryptedBody),
		"encrypted_metadata": b64(em.EncryptedSubject),
	}
	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal encrypted attachment: %w", err)
	}
	return string(jsonBytes), nil
}

// decryptAttachmentJS decrypts an encrypted attachment.
// Args: privKeyB64 (base64 X25519 private key), encryptedJSON (JSON with ephemeral_pubkey, encrypted_key, encrypted_data, encrypted_metadata)
// Returns: JSON { data: base64, metadata: string }
func decryptAttachmentJS(args []js.Value) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("decryptAttachment requires 2+ args: privKeyB64, encryptedJSON, [kemDKB64]")
	}
	privKeyBytes, err := unb64(args[0].String())
	if err != nil {
		return nil, fmt.Errorf("decode privKey: %w", err)
	}
	defer crypto.ZeroBytes(privKeyBytes)
	encJSON := args[1].String()

	// Optional 3rd arg: ML-KEM-768 decapsulation key for hybrid envelopes.
	kemDK, err := parseOptionalKEMDK(args, 2)
	if err != nil {
		return nil, err
	}

	privKey, err := ecdh.X25519().NewPrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	var enc struct {
		EphemeralPubkey   string `json:"ephemeral_pubkey"`
		EncryptedKey      string `json:"encrypted_key"`
		EncryptedData     string `json:"encrypted_data"`
		EncryptedMetadata string `json:"encrypted_metadata"`
	}
	if err := json.Unmarshal([]byte(encJSON), &enc); err != nil {
		return nil, fmt.Errorf("parse encrypted attachment: %w", err)
	}

	ephPub, err := unb64(enc.EphemeralPubkey)
	if err != nil {
		return nil, fmt.Errorf("decode ephemeral pubkey: %w", err)
	}
	encKey, err := unb64(enc.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted key: %w", err)
	}
	encData, err := unb64(enc.EncryptedData)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted data: %w", err)
	}
	encMeta, err := unb64(enc.EncryptedMetadata)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted metadata: %w", err)
	}

	msg := &crypto.EncryptedMessage{
		EphemeralPubkey:     ephPub,
		EncryptedMessageKey: encKey,
		EncryptedBody:       encData,
		EncryptedSubject:    encMeta,
	}

	metadata, data, err := crypto.DecryptMessageAuto(privKey, kemDK, msg)
	if err != nil {
		return nil, err
	}

	result := map[string]string{
		"data":     b64(data),
		"metadata": string(metadata),
	}
	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal decrypted attachment: %w", err)
	}
	return string(jsonBytes), nil
}

// rewrapAttachmentKeyJS re-wraps an attachment key for a different recipient.
// Args: senderPrivKeyB64, recipientPubKeyB64, ephPubB64, encKeyB64
// Returns: JSON { ephemeral_pubkey, encrypted_key }
func rewrapAttachmentKeyJS(args []js.Value) (interface{}, error) {
	if len(args) < 4 {
		return nil, fmt.Errorf("rewrapAttachmentKey requires 4+ args: senderPrivKeyB64, recipientPubKeyB64, ephPubB64, encKeyB64, [senderKEMDKB64], [recipientKEMEKB64]")
	}
	senderPrivBytes, err := unb64(args[0].String())
	if err != nil {
		return nil, fmt.Errorf("decode senderPrivKey: %w", err)
	}
	defer crypto.ZeroBytes(senderPrivBytes)
	recipientPubBytes, err := unb64(args[1].String())
	if err != nil {
		return nil, fmt.Errorf("decode recipientPubKey: %w", err)
	}
	ephPubBytes, err := unb64(args[2].String())
	if err != nil {
		return nil, fmt.Errorf("decode ephPub: %w", err)
	}
	encKeyBytes, err := unb64(args[3].String())
	if err != nil {
		return nil, fmt.Errorf("decode encKey: %w", err)
	}

	// Optional 5th arg: sender's ML-KEM-768 decapsulation key (to unwrap hybrid originals).
	senderKEMDK, err := parseOptionalKEMDK(args, 4)
	if err != nil {
		return nil, err
	}
	// Optional 6th arg: recipient's ML-KEM-768 encapsulation key (to produce hybrid rewrap).
	recipientKEMEK, err := parseOptionalKEMEK(args, 5)
	if err != nil {
		return nil, err
	}

	senderPriv, err := ecdh.X25519().NewPrivateKey(senderPrivBytes)
	if err != nil {
		return nil, fmt.Errorf("parse sender private key: %w", err)
	}
	recipientPub, err := ecdh.X25519().NewPublicKey(recipientPubBytes)
	if err != nil {
		return nil, fmt.Errorf("parse recipient public key: %w", err)
	}

	newEnvelopeKey, newEncKey, err := crypto.RewrapMessageKeyHybrid(
		ephPubBytes, encKeyBytes,
		senderPriv, senderKEMDK,
		recipientPub, recipientKEMEK,
	)
	if err != nil {
		return nil, err
	}

	result := map[string]string{
		"ephemeral_pubkey": b64(newEnvelopeKey),
		"encrypted_key":    b64(newEncKey),
	}
	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal rewrapped key: %w", err)
	}
	return string(jsonBytes), nil
}

// fckWrapKeyJS wraps a 32-byte file message_key under the parent
// folder's FCK using XChaCha20-Poly1305 with file_id bound as AAD.
//
// Construction:
//   nonce = 24 random bytes
//   ad    = file_id_bytes        // bound as AAD
//   blob  = nonce || XChaCha20-Poly1305.Seal(FCK, nonce, message_key, ad)
//
// Why this construction (Donenfeld-style):
//   - Single primitive (XChaCha20-Poly1305) used exactly as designed.
//     It's the same AEAD used everywhere else in the codebase.
//   - 24-byte nonce makes random sampling collision-free for any
//     practical number of wraps (birthday bound ~2^96).
//   - XChaCha20-Poly1305 is safe under a single key for ~2^48
//     messages — orders of magnitude beyond any realistic folder size.
//   - file_id is bound as AAD so a wrapped blob can't be rebound to a
//     different file row by an attacker with DB write access.
//   - No KDF dance, no exotic constructions, no nonce-management
//     state. Random nonce + large nonce space = misuse-resistant.
//
// Args: fckB64 (32 bytes), fileIDStr (UUID string — bound as AAD),
//       messageKeyB64 (32 bytes).
// Returns: base64(nonce || ciphertext || tag) — 24 + 32 + 16 = 72 bytes.
func fckWrapKeyJS(args []js.Value) (interface{}, error) {
	if len(args) < 3 {
		return nil, fmt.Errorf("fckWrapKey requires 3 args: fckB64, fileIDStr, messageKeyB64")
	}
	fck, err := unb64(args[0].String())
	if err != nil {
		return nil, fmt.Errorf("decode fck: %w", err)
	}
	defer crypto.ZeroBytes(fck)
	if len(fck) != 32 {
		return nil, fmt.Errorf("fck must be 32 bytes, got %d", len(fck))
	}
	fileIDBytes := []byte(args[1].String())
	if len(fileIDBytes) == 0 {
		return nil, fmt.Errorf("file_id must not be empty")
	}
	messageKey, err := unb64(args[2].String())
	if err != nil {
		return nil, fmt.Errorf("decode messageKey: %w", err)
	}
	defer crypto.ZeroBytes(messageKey)
	if len(messageKey) != 32 {
		return nil, fmt.Errorf("messageKey must be 32 bytes, got %d", len(messageKey))
	}

	aead, err := chacha20poly1305.NewX(fck)
	if err != nil {
		return nil, fmt.Errorf("init xchacha20: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}
	// Seal appends ciphertext+tag to nonce.
	out := aead.Seal(nonce, nonce, messageKey, fileIDBytes)
	return b64(out), nil
}

// fckUnwrapKeyJS reverses fckWrapKey, returning the plaintext
// message_key. See fckWrapKeyJS for the construction.
//
// Args: fckB64, fileIDStr, wrappedB64.
// Returns: base64-encoded 32-byte message_key.
func fckUnwrapKeyJS(args []js.Value) (interface{}, error) {
	if len(args) < 3 {
		return nil, fmt.Errorf("fckUnwrapKey requires 3 args: fckB64, fileIDStr, wrappedB64")
	}
	fck, err := unb64(args[0].String())
	if err != nil {
		return nil, fmt.Errorf("decode fck: %w", err)
	}
	defer crypto.ZeroBytes(fck)
	if len(fck) != 32 {
		return nil, fmt.Errorf("fck must be 32 bytes, got %d", len(fck))
	}
	fileIDBytes := []byte(args[1].String())
	if len(fileIDBytes) == 0 {
		return nil, fmt.Errorf("file_id must not be empty")
	}
	wrapped, err := unb64(args[2].String())
	if err != nil {
		return nil, fmt.Errorf("decode wrapped: %w", err)
	}

	aead, err := chacha20poly1305.NewX(fck)
	if err != nil {
		return nil, fmt.Errorf("init xchacha20: %w", err)
	}
	if len(wrapped) < aead.NonceSize()+aead.Overhead() {
		return nil, fmt.Errorf("wrapped blob too short")
	}
	nonce := wrapped[:aead.NonceSize()]
	ct := wrapped[aead.NonceSize():]
	messageKey, err := aead.Open(nil, nonce, ct, fileIDBytes)
	if err != nil {
		return nil, fmt.Errorf("xchacha open: %w", err)
	}
	return b64(messageKey), nil
}
