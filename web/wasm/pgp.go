//go:build js && wasm

package main

import (
	"encoding/json"
	"fmt"
	"syscall/js"

	"github.com/bmailag/bmail/internal/crypto"
)

// ── PGP (OpenPGP interoperability) ───────────────────────────

// pgpGenerateKey generates a new OpenPGP key for the given email.
// Returns: { armored_private: string, armored_public: string, fingerprint: string }
func pgpGenerateKey(args []js.Value) (interface{}, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("pgpGenerateKey requires 1 arg: email")
	}
	email := args[0].String()

	privArmored, pubArmored, err := crypto.GeneratePGPKey(email)
	if err != nil {
		return nil, err
	}

	fp, _ := crypto.GetPGPFingerprint(pubArmored)

	return toJSObject(map[string]interface{}{
		"armored_private": privArmored,
		"armored_public":  pubArmored,
		"fingerprint":     fp,
	}), nil
}

// pgpEncryptMessageJS encrypts a message to PGP recipients.
// Args: recipientArmoredKeys (JSON array of strings), subject, body
// Returns: armored PGP message string
func pgpEncryptMessageJS(args []js.Value) (interface{}, error) {
	if len(args) < 3 {
		return nil, fmt.Errorf("pgpEncryptMessage requires 3 args: recipientKeysJSON, subject, body")
	}

	var recipientKeys []string
	if err := json.Unmarshal([]byte(args[0].String()), &recipientKeys); err != nil {
		return nil, fmt.Errorf("parse recipient keys: %w", err)
	}

	subject := args[1].String()
	body := args[2].String()

	armored, err := crypto.PGPEncryptMessage(recipientKeys, subject, body)
	if err != nil {
		return nil, err
	}

	return armored, nil
}

// pgpDecryptMessageJS decrypts a PGP message.
// Args: armoredPrivateKey, armoredMessage, [passphrase]
// Returns: decrypted plaintext string
func pgpDecryptMessageJS(args []js.Value) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("pgpDecryptMessage requires 2 args: armoredPrivateKey, armoredMessage [, passphrase]")
	}

	privKey := args[0].String()
	message := args[1].String()

	// Optional 3rd argument: passphrase for locked keys.
	passphrase := ""
	if len(args) >= 3 && args[2].Type() == js.TypeString {
		passphrase = args[2].String()
	}

	var decrypted []byte
	var err error
	if passphrase != "" {
		decrypted, err = crypto.PGPDecryptMessageWithPassphrase(privKey, passphrase, message)
	} else {
		decrypted, err = crypto.PGPDecryptMessage(privKey, message)
	}
	if err != nil {
		return nil, err
	}

	return string(decrypted), nil
}

// pgpSignMessageJS creates a PGP signature.
// Args: armoredPrivateKey, message, [passphrase]
// Returns: armored signature string
func pgpSignMessageJS(args []js.Value) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("pgpSignMessage requires 2 args: armoredPrivateKey, message [, passphrase]")
	}

	privKey := args[0].String()
	message := []byte(args[1].String())

	// Optional 3rd argument: passphrase for locked keys.
	passphrase := ""
	if len(args) >= 3 && args[2].Type() == js.TypeString {
		passphrase = args[2].String()
	}

	var sig string
	var err error
	if passphrase != "" {
		sig, err = crypto.PGPSignMessageWithPassphrase(privKey, passphrase, message)
	} else {
		sig, err = crypto.PGPSignMessage(privKey, message)
	}
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// pgpVerifySignatureJS verifies a PGP signature.
// Args: armoredPublicKey, message, armoredSignature
// Returns: boolean
func pgpVerifySignatureJS(args []js.Value) (interface{}, error) {
	if len(args) < 3 {
		return nil, fmt.Errorf("pgpVerifySignature requires 3 args: armoredPublicKey, message, armoredSignature")
	}

	valid, err := crypto.PGPVerifySignature(args[0].String(), []byte(args[1].String()), args[2].String())
	if err != nil {
		return nil, err
	}

	return valid, nil
}

// pgpGetFingerprintJS returns the fingerprint of a PGP key.
func pgpGetFingerprintJS(args []js.Value) (interface{}, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("pgpGetFingerprint requires 1 arg: armoredKey")
	}

	fp, err := crypto.GetPGPFingerprint(args[0].String())
	if err != nil {
		return nil, err
	}

	return fp, nil
}

// pgpExportPublicKeyJS extracts the armored public key from a private key.
func pgpExportPublicKeyJS(args []js.Value) (interface{}, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("pgpExportPublicKey requires 1 arg: armoredPrivateKey")
	}

	key, err := crypto.PGPPublicKeyFromArmored(args[0].String())
	if err != nil {
		return nil, err
	}

	armored, err := key.GetArmoredPublicKey()
	if err != nil {
		return nil, fmt.Errorf("armor public key: %w", err)
	}

	return armored, nil
}
