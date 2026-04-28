//go:build js && wasm

package main

import (
	"encoding/json"
	"fmt"
	"syscall/js"

	"github.com/bytemare/opaque"

	"github.com/bmailag/bmail/internal/crypto"
)

// ── OPAQUE ──────────────────────────────────────────────────

// opaqueConf returns the default OPAQUE configuration (must match the server's).
func opaqueConf() *opaque.Configuration {
	return opaque.DefaultConfiguration()
}

func opaqueRegistrationStart(args []js.Value) (interface{}, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("opaqueRegistrationStart requires 1 arg: password")
	}
	password := []byte(args[0].String())

	if len(password) == 0 {
		return nil, fmt.Errorf("password must not be empty")
	}
	if len(password) > 512 {
		return nil, fmt.Errorf("password must not exceed 512 bytes, got %d", len(password))
	}

	// Enforce password strength during registration.
	// Server cannot validate (OPAQUE prevents server from seeing the password),
	// so validation must happen client-side in WASM.
	if err := validatePasswordStrength(string(password)); err != nil {
		return nil, err
	}

	conf := opaqueConf()
	client, err := conf.Client()
	if err != nil {
		return nil, fmt.Errorf("create OPAQUE client: %w", err)
	}

	regReq := client.RegistrationInit(password)
	regReqBytes := regReq.Serialize()

	// Store client for the subsequent Finish call.
	clientID, err := storeClient(client)
	if err != nil {
		return nil, err
	}

	result := map[string]string{
		"opaque_message": b64(regReqBytes),
		"client_id":      clientID,
	}
	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return string(jsonBytes), nil
}

func opaqueRegistrationFinish(args []js.Value) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("opaqueRegistrationFinish requires 2 args: clientID, serverResponseBase64")
	}
	clientID := args[0].String()
	serverRespB64 := args[1].String()

	client, err := takeClient(clientID)
	if err != nil {
		return nil, fmt.Errorf("registration finish: %w", err)
	}

	serverRespBytes, err := unb64(serverRespB64)
	if err != nil {
		return nil, fmt.Errorf("decode server response: %w", err)
	}

	regResp, err := client.Deserialize.RegistrationResponse(serverRespBytes)
	if err != nil {
		return nil, fmt.Errorf("deserialize registration response: %w", err)
	}

	record, exportKey := client.RegistrationFinalize(regResp)
	defer crypto.ZeroBytes(exportKey)
	recordBytes := record.Serialize()

	// Derive 32-byte encryption key from OPAQUE export key (may be 64 bytes).
	encKey := deriveEncKey(exportKey)
	defer crypto.ZeroBytes(encKey)

	// Generate keypairs.
	encKP, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate encryption keypair: %w", err)
	}
	sigKP, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate signing keypair: %w", err)
	}
	kemKP, err := crypto.GenerateMLKEMKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate ML-KEM-768 keypair: %w", err)
	}

	// Bundle all private keys as JSON, then encrypt with derived key.
	// The KEM decapsulation key (seed form, 64 bytes) is included in the bundle.
	allPrivKeys, err := json.Marshal(map[string]string{
		"encryption": b64(encKP.Private.Bytes()),
		"signing":    b64(sigKP.Private),
		"kem":        b64(kemKP.DecapsulationKey.Bytes()),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal private keys: %w", err)
	}
	defer crypto.ZeroBytes(allPrivKeys)

	encryptedPrivKey, err := crypto.EncryptPrivateKey(allPrivKeys, encKey, crypto.AADPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("encrypt private keys: %w", err)
	}

	// Encrypt the KEM decapsulation key separately under a distinct AAD
	// so it can be stored and retrieved independently.
	encryptedKEMPriv, err := crypto.EncryptPrivateKey(kemKP.DecapsulationKey.Bytes(), encKey, crypto.AADPrivateKeyKEM)
	if err != nil {
		return nil, fmt.Errorf("encrypt KEM private key: %w", err)
	}

	// Generate recovery mnemonic and encrypt private key with recovery key.
	// Use V3 (user-bound) derivation if email address is provided (3rd arg).
	mnemonic, err := crypto.GenerateMnemonic()
	if err != nil {
		return nil, fmt.Errorf("generate mnemonic: %w", err)
	}

	var recoveryKey [32]byte
	if len(args) >= 3 && args[2].String() != "" {
		recoveryKey, err = crypto.DeriveRecoveryKeyV3(mnemonic, args[2].String())
	} else {
		recoveryKey, err = crypto.DeriveRecoveryKey(mnemonic)
	}
	if err != nil {
		return nil, fmt.Errorf("derive recovery key: %w", err)
	}
	defer crypto.ZeroBytes(recoveryKey[:])

	encryptedRecoveryKey, err := crypto.EncryptWithRecoveryKey(allPrivKeys, recoveryKey)
	if err != nil {
		return nil, fmt.Errorf("encrypt with recovery key: %w", err)
	}

	// SECURITY NOTE: The recovery mnemonic is returned as a JS string, which is
	// immutable and cannot be zeroed in browser memory. This is an inherent
	// limitation of the WASM-in-browser architecture. The frontend should display
	// the mnemonic only once, avoid storing it in application state, and instruct
	// the user to write it down physically.
	result := map[string]string{
		"opaque_message":             b64(recordBytes),
		"export_key":                 b64(encKey),
		"public_key_encryption":      b64(encKP.Public.Bytes()),
		"public_key_signing":         b64(sigKP.Public),
		"public_key_kem":             b64(kemKP.EncapsulationKey.Bytes()),
		"encrypted_private_key":      b64(encryptedPrivKey),
		"encrypted_private_key_kem":  b64(encryptedKEMPriv),
		"encrypted_recovery_key":     b64(encryptedRecoveryKey),
		"recovery_mnemonic":          mnemonic,
	}
	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return string(jsonBytes), nil
}

// opaqueRecoveryRegistrationFinish finalizes an OPAQUE registration for
// recovery purposes only. Unlike opaqueRegistrationFinish, this does NOT
// generate keypairs or a mnemonic — it just finalizes the OPAQUE registration
// and returns the record + derived recovery encryption key.
func opaqueRecoveryRegistrationFinish(args []js.Value) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("opaqueRecoveryRegistrationFinish requires 2 args: clientID, serverResponseBase64")
	}
	clientID := args[0].String()
	serverRespB64 := args[1].String()

	client, err := takeClient(clientID)
	if err != nil {
		return nil, fmt.Errorf("recovery registration finish: %w", err)
	}

	serverRespBytes, err := unb64(serverRespB64)
	if err != nil {
		return nil, fmt.Errorf("decode server response: %w", err)
	}

	regResp, err := client.Deserialize.RegistrationResponse(serverRespBytes)
	if err != nil {
		return nil, fmt.Errorf("deserialize registration response: %w", err)
	}

	record, exportKey := client.RegistrationFinalize(regResp)
	defer crypto.ZeroBytes(exportKey)
	recordBytes := record.Serialize()

	// Return raw export key — encryptRecoveryBlob derives the encryption key internally.
	result := map[string]string{
		"opaque_message": b64(recordBytes),
		"export_key":     b64(exportKey),
	}
	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return string(jsonBytes), nil
}

func opaqueLoginStart(args []js.Value) (interface{}, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("opaqueLoginStart requires 1 arg: password")
	}
	password := []byte(args[0].String())

	if len(password) == 0 {
		return nil, fmt.Errorf("password must not be empty")
	}
	if len(password) > 512 {
		return nil, fmt.Errorf("password must not exceed 512 bytes, got %d", len(password))
	}

	conf := opaqueConf()
	client, err := conf.Client()
	if err != nil {
		return nil, fmt.Errorf("create OPAQUE client: %w", err)
	}

	ke1 := client.LoginInit(password)
	ke1Bytes := ke1.Serialize()

	// Store client for the subsequent Finish call.
	clientID, err := storeClient(client)
	if err != nil {
		return nil, err
	}

	result := map[string]string{
		"opaque_message": b64(ke1Bytes),
		"client_id":      clientID,
	}
	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return string(jsonBytes), nil
}

func opaqueLoginFinish(args []js.Value) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("opaqueLoginFinish requires 2 args: clientID, serverResponseBase64")
	}
	clientID := args[0].String()
	serverRespB64 := args[1].String()

	client, err := takeClient(clientID)
	if err != nil {
		return nil, fmt.Errorf("login finish: %w", err)
	}

	serverRespBytes, err := unb64(serverRespB64)
	if err != nil {
		return nil, fmt.Errorf("decode server response: %w", err)
	}

	ke2, err := client.Deserialize.KE2(serverRespBytes)
	if err != nil {
		return nil, fmt.Errorf("deserialize KE2: %w", err)
	}

	ke3, exportKey, err := client.LoginFinish(ke2)
	if err != nil {
		return nil, fmt.Errorf("login finish: %w", err)
	}
	defer crypto.ZeroBytes(exportKey)

	// Derive encryption keys from OPAQUE export key.
	// V2 (with salt) is preferred; V1 (nil salt) is provided for backward
	// compatibility with accounts registered before the salt fix.
	// The frontend should try V2 first; if decryption fails, fall back to V1,
	// then re-encrypt with V2 on next password change.
	encKeyV2 := deriveEncKey(exportKey)
	defer crypto.ZeroBytes(encKeyV2)
	encKeyV1 := deriveEncKeyV1(exportKey)
	defer crypto.ZeroBytes(encKeyV1)

	result := map[string]string{
		"opaque_message":        b64(ke3.Serialize()),
		"export_key":            b64(encKeyV2),
		"export_key_v1":         b64(encKeyV1),
		"export_key_recovery":   b64(exportKey),
	}
	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return string(jsonBytes), nil
}
