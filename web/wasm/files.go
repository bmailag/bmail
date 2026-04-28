//go:build js && wasm

package main

import (
	"crypto/ecdh"
	"encoding/json"
	"fmt"
	"syscall/js"

	"github.com/bmailag/bmail/internal/crypto"
)

// ── File Encryption ─────────────────────────────────────────

func encryptFile(args []js.Value) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("encryptFile requires 2+ args: recipientPubKey, data (base64), [kemEKB64]")
	}
	pubKeyBytes, err := unb64(args[0].String())
	if err != nil {
		return nil, fmt.Errorf("decode recipientPubKey: %w", err)
	}
	dataBytes, err := unb64(args[1].String())
	if err != nil {
		return nil, fmt.Errorf("decode data: %w", err)
	}

	// Optional 3rd arg: recipient's ML-KEM-768 encapsulation key for hybrid.
	kemEK, err := parseOptionalKEMEK(args, 2)
	if err != nil {
		return nil, err
	}

	pubKey, err := ecdh.X25519().NewPublicKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse recipient public key: %w", err)
	}

	em, err := crypto.EncryptMessageHybrid(pubKey, kemEK, []byte{}, dataBytes)
	if err != nil {
		return nil, err
	}

	fileResult := map[string]string{
		"ephemeral_pubkey":      b64(em.EphemeralPubkey),
		"encrypted_message_key": b64(em.EncryptedMessageKey),
		"encrypted_body":        b64(em.EncryptedBody),
		"encrypted_subject":     b64(em.EncryptedSubject),
	}
	jsonBytes, err := json.Marshal(fileResult)
	if err != nil {
		return nil, fmt.Errorf("marshal encrypted file: %w", err)
	}
	return string(jsonBytes), nil
}

func decryptFile(args []js.Value) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("decryptFile requires 2+ args: privateKey, encryptedJSON, [kemDKB64]")
	}
	privKeyBytes, err := unb64(args[0].String())
	if err != nil {
		return nil, fmt.Errorf("decode privateKey: %w", err)
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

	var fileMsg struct {
		EphemeralPubkey     string `json:"ephemeral_pubkey"`
		EncryptedMessageKey string `json:"encrypted_message_key"`
		EncryptedBody       string `json:"encrypted_body"`
		EncryptedSubject    string `json:"encrypted_subject"`
	}
	if err := json.Unmarshal([]byte(encJSON), &fileMsg); err != nil {
		return nil, fmt.Errorf("parse encrypted file: %w", err)
	}

	ephPub, err := unb64(fileMsg.EphemeralPubkey)
	if err != nil {
		return nil, fmt.Errorf("decode ephemeral pubkey: %w", err)
	}
	encMK, err := unb64(fileMsg.EncryptedMessageKey)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted message key: %w", err)
	}
	encBody, err := unb64(fileMsg.EncryptedBody)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted body: %w", err)
	}

	// For file encryption, encrypted_subject contains an encrypted empty byte slice.
	var encSubject []byte
	if fileMsg.EncryptedSubject != "" {
		encSubject, err = unb64(fileMsg.EncryptedSubject)
		if err != nil {
			return nil, fmt.Errorf("decode encrypted subject: %w", err)
		}
	}

	msg := &crypto.EncryptedMessage{
		EphemeralPubkey:     ephPub,
		EncryptedMessageKey: encMK,
		EncryptedBody:       encBody,
		EncryptedSubject:    encSubject,
	}

	_, body, err := crypto.DecryptMessageAuto(privKey, kemDK, msg)
	if err != nil {
		return nil, err
	}

	return b64(body), nil
}
