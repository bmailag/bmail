//go:build js && wasm

package main

import (
	"crypto/ecdh"
	"encoding/json"
	"fmt"
	"syscall/js"

	"github.com/bmailag/bmail/internal/crypto"
)

// encryptWithMessageKeyJS encrypts a body + subject using a caller-
// supplied 32-byte message_key, skipping the X25519 envelope step
// (which the caller does separately). Used by the FCK upload paths
// where the uploader needs the plaintext message_key in hand to wrap
// it under FCK *before* encrypting the body.
//
// Args: messageKeyB64 (32 bytes), subject (UTF-8 string),
//       bodyB64 (base64-encoded raw bytes — same convention as
//       encryptMessage's body parameter on the upload path).
// Returns: JSON { encrypted_body, encrypted_subject }
func encryptWithMessageKeyJS(args []js.Value) (interface{}, error) {
	if len(args) < 3 {
		return nil, fmt.Errorf("encryptWithMessageKey requires 3 args: messageKeyB64, subject, bodyB64")
	}
	messageKey, err := unb64(args[0].String())
	if err != nil {
		return nil, fmt.Errorf("decode messageKey: %w", err)
	}
	defer crypto.ZeroBytes(messageKey)
	if len(messageKey) != 32 {
		return nil, fmt.Errorf("invalid message key length: %d", len(messageKey))
	}
	subject := args[1].String()
	body, err := unb64(args[2].String())
	if err != nil {
		return nil, fmt.Errorf("decode body: %w", err)
	}

	// Use the same AEAD + AAD bindings as crypto.EncryptMessage's body
	// and subject sealing steps so the legacy decrypt path
	// (DecryptMessage) can read what we wrote.
	encBody, err := crypto.SealWrappedKey(messageKey, body, []byte("body"))
	if err != nil {
		return nil, fmt.Errorf("encrypt body: %w", err)
	}
	var encSubject []byte
	if subject != "" {
		encSubject, err = crypto.SealWrappedKey(messageKey, []byte(subject), []byte("subject"))
		if err != nil {
			return nil, fmt.Errorf("encrypt subject: %w", err)
		}
	}

	result := map[string]string{
		"encrypted_body":    b64(encBody),
		"encrypted_subject": b64(encSubject),
	}
	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal encrypted: %w", err)
	}
	return string(jsonBytes), nil
}

// decryptMessageWithKeyJS decrypts a message body using a plaintext
// message_key directly, skipping the X25519 unwrap step. Used by the
// FCK shared download path: the recipient already has the plaintext
// message_key (recovered via aesGcmUnwrapMessageKey from the FCK)
// and just needs to decrypt the body with it.
//
// Args: messageKeyB64 (32-byte AEAD key), encryptedBodyB64,
//       encryptedSubjectB64 (may be empty).
// Returns: JSON { body: base64, subject: string }
func decryptMessageWithKeyJS(args []js.Value) (interface{}, error) {
	if len(args) < 3 {
		return nil, fmt.Errorf("decryptMessageWithKey requires 3 args: messageKeyB64, encryptedBodyB64, encryptedSubjectB64")
	}
	messageKey, err := unb64(args[0].String())
	if err != nil {
		return nil, fmt.Errorf("decode messageKey: %w", err)
	}
	defer crypto.ZeroBytes(messageKey)
	var encBody []byte
	if args[1].String() != "" {
		encBody, err = unb64(args[1].String())
		if err != nil {
			return nil, fmt.Errorf("decode encryptedBody: %w", err)
		}
	}
	var encSubject []byte
	if args[2].String() != "" {
		encSubject, err = unb64(args[2].String())
		if err != nil {
			return nil, fmt.Errorf("decode encryptedSubject: %w", err)
		}
	}

	var body []byte
	if len(encBody) > 0 {
		body, err = crypto.OpenWrappedKey(messageKey, encBody, []byte("body"))
		if err != nil {
			return nil, fmt.Errorf("decrypt body: %w", err)
		}
	}
	var subject []byte
	if len(encSubject) > 0 {
		subject, err = crypto.OpenWrappedKey(messageKey, encSubject, []byte("subject"))
		if err != nil {
			return nil, fmt.Errorf("decrypt subject: %w", err)
		}
	}

	result := map[string]string{
		"body":    b64(body),
		"subject": string(subject),
	}
	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal decrypted: %w", err)
	}
	return string(jsonBytes), nil
}

// unwrapMessageKeyJS unwraps an attachment/file message_key with the
// recipient's X25519 private key, returning the plaintext key. The
// inverse half of rewrapAttachmentKeyJS, exposed separately so the
// FCK share flow can extract a file's message_key without immediately
// re-wrapping it (FCK wraps via AES-GCM, not X25519).
//
// Args: privKeyB64, ephPubB64, encKeyB64
// Returns: base64-encoded message_key (typically 32 bytes).
func unwrapMessageKeyJS(args []js.Value) (interface{}, error) {
	if len(args) < 3 {
		return nil, fmt.Errorf("unwrapMessageKey requires 3+ args: privKeyB64, ephPubB64, encKeyB64, [kemDKB64]")
	}
	privKeyBytes, err := unb64(args[0].String())
	if err != nil {
		return nil, fmt.Errorf("decode privKey: %w", err)
	}
	defer crypto.ZeroBytes(privKeyBytes)
	ephPubBytes, err := unb64(args[1].String())
	if err != nil {
		return nil, fmt.Errorf("decode ephPub: %w", err)
	}
	encKeyBytes, err := unb64(args[2].String())
	if err != nil {
		return nil, fmt.Errorf("decode encKey: %w", err)
	}

	// Optional 4th arg: ML-KEM-768 decapsulation key for hybrid envelopes.
	// When provided, uses UnwrapEnvelope which auto-detects classical vs hybrid.
	kemDK, err := parseOptionalKEMDK(args, 3)
	if err != nil {
		return nil, err
	}

	privKey, err := ecdh.X25519().NewPrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	// Use UnwrapEnvelope for auto-detection of classical (32-byte) vs
	// hybrid (1121-byte) envelope keys. For classical envelopes without
	// a KEM DK, this falls through to the same ECDH + HKDF path.
	messageKey, err := crypto.UnwrapEnvelope(privKey, kemDK, ephPubBytes, encKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("unwrap message key: %w", err)
	}
	return b64(messageKey), nil
}

// wrapMessageKeyJS wraps a plaintext message_key for a recipient's
// X25519 pubkey using the standard envelope (ephemeral keypair +
// HKDF + XChaCha20-Poly1305). Used by the FCK share flow to wrap the
// FCK itself for the owner and each recipient before stashing the
// wraps on the folder row / share row.
//
// Args: recipientPubKeyB64, messageKeyB64
// Returns: JSON { ephemeral_pubkey, encrypted_key }
func wrapMessageKeyJS(args []js.Value) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("wrapMessageKey requires 2+ args: recipientPubKeyB64, messageKeyB64, [kemEKB64]")
	}
	recipientPubBytes, err := unb64(args[0].String())
	if err != nil {
		return nil, fmt.Errorf("decode recipientPubKey: %w", err)
	}
	messageKey, err := unb64(args[1].String())
	if err != nil {
		return nil, fmt.Errorf("decode messageKey: %w", err)
	}
	defer crypto.ZeroBytes(messageKey)

	// Optional 3rd arg: recipient's ML-KEM-768 encapsulation key for hybrid.
	kemEK, err := parseOptionalKEMEK(args, 2)
	if err != nil {
		return nil, err
	}

	if len(recipientPubBytes) != 32 {
		return nil, fmt.Errorf("invalid recipient pubkey length: %d", len(recipientPubBytes))
	}
	recipientPub, err := ecdh.X25519().NewPublicKey(recipientPubBytes)
	if err != nil {
		return nil, fmt.Errorf("parse recipient pubkey: %w", err)
	}

	// Use WrapEnvelope which auto-selects classical or hybrid based on
	// whether kemEK is provided. Returns envelope key (32-byte eph pubkey
	// for classical, 1121-byte version+eph+kemCT for hybrid) and the
	// AEAD-sealed message key.
	envelopeKey, encKey, err := crypto.WrapEnvelope(recipientPub, kemEK, messageKey)
	if err != nil {
		return nil, fmt.Errorf("wrap message key: %w", err)
	}

	result := map[string]string{
		"ephemeral_pubkey": b64(envelopeKey),
		"encrypted_key":    b64(encKey),
	}
	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal wrapped key: %w", err)
	}
	return string(jsonBytes), nil
}
