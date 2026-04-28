//go:build js && wasm

package main

import (
	"crypto/ecdh"
	"encoding/json"
	"fmt"
	"syscall/js"

	"github.com/bmailag/bmail/internal/crypto"
)

// ── Message Encryption ──────────────────────────────────────

func encryptMessage(args []js.Value) (interface{}, error) {
	if len(args) < 3 {
		return nil, fmt.Errorf("encryptMessage requires 3+ args: recipientPubKey, subject, body, [headersJSON], [kemEKB64]")
	}
	pubKeyBytes, err := unb64(args[0].String())
	if err != nil {
		return nil, fmt.Errorf("decode recipientPubKey: %w", err)
	}
	subject := args[1].String()
	body := args[2].String()

	// Phase B3: optional 4th arg is the RFC 5322 headers JSON. When
	// supplied it's encrypted under the same message key as the body
	// and subject (AAD "headers") and returned in the encrypted_headers
	// slot. Callers that don't yet need headers pass undefined and
	// the result has only the legacy fields.
	var headers []byte
	if len(args) >= 4 && !args[3].IsUndefined() && !args[3].IsNull() {
		headers = []byte(args[3].String())
	}

	// Optional 5th arg: recipient's ML-KEM-768 encapsulation key for
	// hybrid post-quantum key exchange. When provided, uses
	// EncryptMessageWithHeadersHybrid; otherwise classical.
	kemEK, err := parseOptionalKEMEK(args, 4)
	if err != nil {
		return nil, err
	}

	pubKey, err := ecdh.X25519().NewPublicKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse recipient public key: %w", err)
	}

	em, err := crypto.EncryptMessageWithHeadersHybrid(pubKey, kemEK, []byte(subject), []byte(body), headers)
	if err != nil {
		return nil, err
	}

	// Return as JSON string for easy transport.
	result := map[string]string{
		"ephemeral_pubkey":      b64(em.EphemeralPubkey),
		"encrypted_message_key": b64(em.EncryptedMessageKey),
		"encrypted_body":        b64(em.EncryptedBody),
		"encrypted_subject":     b64(em.EncryptedSubject),
	}
	if len(em.EncryptedHeaders) > 0 {
		result["encrypted_headers"] = b64(em.EncryptedHeaders)
	}
	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal encrypted message: %w", err)
	}
	return string(jsonBytes), nil
}

func decryptMessage(args []js.Value) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("decryptMessage requires 2+ args: privateKey, encryptedMessageJSON, [kemDKB64]")
	}
	privKeyBytes, err := unb64(args[0].String())
	if err != nil {
		return nil, fmt.Errorf("decode privateKey: %w", err)
	}
	defer crypto.ZeroBytes(privKeyBytes)
	encJSON := args[1].String()

	// Optional 3rd arg: user's ML-KEM-768 decapsulation key for hybrid
	// envelope unwrapping. Auto-detect handles classical vs hybrid.
	kemDK, err := parseOptionalKEMDK(args, 2)
	if err != nil {
		return nil, err
	}

	privKey, err := ecdh.X25519().NewPrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	var em struct {
		EphemeralPubkey     string `json:"ephemeral_pubkey"`
		EncryptedMessageKey string `json:"encrypted_message_key"`
		EncryptedBody       string `json:"encrypted_body"`
		EncryptedSubject    string `json:"encrypted_subject"`
	}
	if err := json.Unmarshal([]byte(encJSON), &em); err != nil {
		return nil, fmt.Errorf("parse encrypted message: %w", err)
	}

	ephPub, err := unb64(em.EphemeralPubkey)
	if err != nil {
		return nil, fmt.Errorf("decode ephemeral pubkey: %w", err)
	}
	encMK, err := unb64(em.EncryptedMessageKey)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted message key: %w", err)
	}
	encBody, err := unb64(em.EncryptedBody)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted body: %w", err)
	}
	encSubject, err := unb64(em.EncryptedSubject)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted subject: %w", err)
	}

	msg := &crypto.EncryptedMessage{
		EphemeralPubkey:     ephPub,
		EncryptedMessageKey: encMK,
		EncryptedBody:       encBody,
		EncryptedSubject:    encSubject,
	}

	subject, body, err := crypto.DecryptMessageAuto(privKey, kemDK, msg)
	if err != nil {
		return nil, err
	}

	return toJSObject(map[string]interface{}{
		"subject": string(subject),
		"body":    string(body),
	}), nil
}

// decryptRawSource decrypts a raw message source envelope (supports both single-block and chunked).
// Args: privateKey (base64), sourceJSON (string with ephemeral_pubkey, encrypted_message_key,
//       encrypted_body, raw_blob_format, and optionally encrypted_raw_meta)
// Returns: JS object { body: string, meta?: string }
func decryptRawSource(args []js.Value) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("decryptRawSource requires 2+ args: privateKey, sourceJSON, [kemDKB64]")
	}
	privKeyBytes, err := unb64(args[0].String())
	if err != nil {
		return nil, fmt.Errorf("decode privateKey: %w", err)
	}
	defer crypto.ZeroBytes(privKeyBytes)

	// Optional 3rd arg: ML-KEM-768 decapsulation key for hybrid envelopes.
	kemDK, err := parseOptionalKEMDK(args, 2)
	if err != nil {
		return nil, err
	}

	privKey, err := ecdh.X25519().NewPrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	var envelope struct {
		EphemeralPubkey     string `json:"ephemeral_pubkey"`
		EncryptedMessageKey string `json:"encrypted_message_key"`
		EncryptedBody       string `json:"encrypted_body"`
		RawBlobFormat       string `json:"raw_blob_format"`
		EncryptedRawMeta    string `json:"encrypted_raw_meta"`
	}
	if err := json.Unmarshal([]byte(args[1].String()), &envelope); err != nil {
		return nil, fmt.Errorf("parse source envelope: %w", err)
	}

	ephPub, err := unb64(envelope.EphemeralPubkey)
	if err != nil {
		return nil, fmt.Errorf("decode ephemeral pubkey: %w", err)
	}
	encMK, err := unb64(envelope.EncryptedMessageKey)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted message key: %w", err)
	}
	encBody, err := unb64(envelope.EncryptedBody)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted body: %w", err)
	}
	var encMeta []byte
	if envelope.EncryptedRawMeta != "" {
		encMeta, err = unb64(envelope.EncryptedRawMeta)
		if err != nil {
			encMeta = nil // non-fatal
		}
	}

	msg := &crypto.EncryptedMessage{
		EphemeralPubkey:     ephPub,
		EncryptedMessageKey: encMK,
		EncryptedBody:       encBody,
	}

	body, meta, err := crypto.DecryptRawMessageAuto(privKey, kemDK, msg, envelope.RawBlobFormat, encMeta)
	if err != nil {
		return nil, err
	}

	result := map[string]interface{}{
		"body": string(body),
	}
	if meta != nil {
		result["meta"] = string(meta)
	}
	return toJSObject(result), nil
}

// decryptSubjectOnly decrypts only the subject without requiring the encrypted body.
// Args: privateKey (base64), ephemeralPubkey (base64), encryptedMessageKey (base64), encryptedSubject (base64)
// Returns: string (decrypted subject)
func decryptSubjectOnly(args []js.Value) (interface{}, error) {
	if len(args) < 4 {
		return nil, fmt.Errorf("decryptSubject requires 4+ args: privateKey, ephemeralPubkey, encryptedMessageKey, encryptedSubject, [kemDKB64]")
	}
	privKeyBytes, err := unb64(args[0].String())
	if err != nil {
		return nil, fmt.Errorf("decode privateKey: %w", err)
	}
	defer crypto.ZeroBytes(privKeyBytes)
	ephPub, err := unb64(args[1].String())
	if err != nil {
		return nil, fmt.Errorf("decode ephemeralPubkey: %w", err)
	}
	encMK, err := unb64(args[2].String())
	if err != nil {
		return nil, fmt.Errorf("decode encryptedMessageKey: %w", err)
	}
	encSubject, err := unb64(args[3].String())
	if err != nil {
		return nil, fmt.Errorf("decode encryptedSubject: %w", err)
	}

	// Optional 5th arg: ML-KEM-768 decapsulation key for hybrid envelopes.
	kemDK, err := parseOptionalKEMDK(args, 4)
	if err != nil {
		return nil, err
	}

	privKey, err := ecdh.X25519().NewPrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	subject, err := crypto.DecryptSubjectOnlyAuto(privKey, kemDK, ephPub, encMK, encSubject)
	if err != nil {
		return nil, err
	}
	return string(subject), nil
}

// decryptHeaders decrypts the Phase B3 headers slot of an encrypted
// message. The headers slot shares the body's message key — same
// envelope (ephemeralPubkey + encryptedMessageKey) — so the client
// can decrypt headers without fetching the body or the raw blob.
//
// Args: privateKey (base64), ephemeralPubkey (base64), encryptedMessageKey (base64), encryptedHeaders (base64)
// Returns: string (the decrypted headers JSON)
func decryptHeaders(args []js.Value) (interface{}, error) {
	if len(args) < 4 {
		return nil, fmt.Errorf("decryptHeaders requires 4+ args: privateKey, ephemeralPubkey, encryptedMessageKey, encryptedHeaders, [kemDKB64]")
	}
	privKeyBytes, err := unb64(args[0].String())
	if err != nil {
		return nil, fmt.Errorf("decode privateKey: %w", err)
	}
	defer crypto.ZeroBytes(privKeyBytes)
	ephPub, err := unb64(args[1].String())
	if err != nil {
		return nil, fmt.Errorf("decode ephemeralPubkey: %w", err)
	}
	encMK, err := unb64(args[2].String())
	if err != nil {
		return nil, fmt.Errorf("decode encryptedMessageKey: %w", err)
	}
	encHeaders, err := unb64(args[3].String())
	if err != nil {
		return nil, fmt.Errorf("decode encryptedHeaders: %w", err)
	}

	// Optional 5th arg: ML-KEM-768 decapsulation key for hybrid envelopes.
	kemDK, err := parseOptionalKEMDK(args, 4)
	if err != nil {
		return nil, err
	}

	privKey, err := ecdh.X25519().NewPrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	headers, err := crypto.DecryptHeadersAuto(privKey, kemDK, ephPub, encMK, encHeaders)
	if err != nil {
		return nil, err
	}
	return string(headers), nil
}
