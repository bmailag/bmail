//go:build js && wasm

// Package main is the WASM crypto module for the Bmail web frontend.
// It exports cryptographic functions to JavaScript via syscall/js.
//
// The implementations are split across files by area:
//
//   helpers.go     — js.Func wrapper, base64, KEM key parsers
//   clients.go     — OPAQUE pending-client registry + cleanup goroutine
//   keys.go        — keypair generation + private-key encryption
//   messages.go    — message encryption / decryption (subject, body, headers, raw)
//   signing.go     — Ed25519 sign / verify
//   recovery.go    — recovery mnemonic + recovery-blob crypto
//   files.go       — file (Drive) encryption / decryption
//   attachments.go — attachment encryption + FCK wrap/unwrap
//   messagekey.go  — direct message-key encrypt/decrypt + envelope wrap/unwrap
//   kt.go          — Key Transparency Merkle proof + signed-root verification
//   pgp.go         — OpenPGP interoperability
//   password.go    — client-side password strength validation
//   opaque.go      — OPAQUE registration + login flows
//   shares.go      — Drive share AES-GCM + PBKDF2 helpers
//   blind.go       — RSA blind-signature primitives (Fake ID flows)
package main

import "syscall/js"

func main() {
	// Register all exported functions on a global vpCrypto object.
	vpCrypto := js.Global().Get("Object").New()

	// Key generation
	vpCrypto.Set("generateKeypair", jsFunc(generateKeypair))
	vpCrypto.Set("generateKEMUpgrade", jsFunc(generateKEMUpgrade))
	vpCrypto.Set("encryptPrivateKey", jsFunc(encryptPrivateKey))
	vpCrypto.Set("decryptPrivateKey", jsFunc(decryptPrivateKey))
	vpCrypto.Set("decryptPrivateKeyKEM", jsFunc(decryptPrivateKeyKEM))

	// Message encryption
	vpCrypto.Set("encryptMessage", jsFunc(encryptMessage))
	vpCrypto.Set("decryptMessage", jsFunc(decryptMessage))
	vpCrypto.Set("decryptSubject", jsFunc(decryptSubjectOnly))
	vpCrypto.Set("decryptHeaders", jsFunc(decryptHeaders))
	vpCrypto.Set("decryptRawSource", jsFunc(decryptRawSource))

	// Signing
	vpCrypto.Set("sign", jsFunc(sign))
	vpCrypto.Set("verify", jsFunc(verify))

	// Recovery
	vpCrypto.Set("generateRecoveryMnemonic", jsFunc(generateRecoveryMnemonic))
	vpCrypto.Set("deriveRecoveryKey", jsFunc(deriveRecoveryKey))
	vpCrypto.Set("deriveRecoveryKeyV3", jsFunc(deriveRecoveryKeyV3))
	vpCrypto.Set("encryptWithRecoveryKey", jsFunc(encryptWithRecoveryKey))
	vpCrypto.Set("decryptWithRecoveryKey", jsFunc(decryptWithRecoveryKey))
	vpCrypto.Set("encryptRecoveryBlob", jsFunc(encryptRecoveryBlob))
	vpCrypto.Set("decryptRecoveryBlob", jsFunc(decryptRecoveryBlob))

	// File encryption
	vpCrypto.Set("encryptFile", jsFunc(encryptFile))
	vpCrypto.Set("decryptFile", jsFunc(decryptFile))

	// Attachment encryption (E2E encrypted attachments)
	vpCrypto.Set("encryptAttachment", jsFunc(encryptAttachmentJS))
	vpCrypto.Set("decryptAttachment", jsFunc(decryptAttachmentJS))
	vpCrypto.Set("rewrapAttachmentKey", jsFunc(rewrapAttachmentKeyJS))
	// Standalone wrap/unwrap of a 32-byte key under an X25519 pubkey.
	// Used by the Phase B FCK share flow to wrap the FCK itself.
	vpCrypto.Set("unwrapMessageKey", jsFunc(unwrapMessageKeyJS))
	vpCrypto.Set("wrapMessageKey", jsFunc(wrapMessageKeyJS))
	// Encrypt / decrypt a message body with a plaintext message_key
	// (FCK paths — uploader holds the key directly).
	vpCrypto.Set("encryptWithMessageKey", jsFunc(encryptWithMessageKeyJS))
	vpCrypto.Set("decryptMessageWithKey", jsFunc(decryptMessageWithKeyJS))
	// FCK file-key wrap/unwrap: HKDF-derived per-file key + XChaCha20-Poly1305.
	// Donenfeld-style: misuse-resistant primitive (24-byte nonce),
	// per-file domain separation, file_id bound as both salt + AAD.
	vpCrypto.Set("fckWrapKey", jsFunc(fckWrapKeyJS))
	vpCrypto.Set("fckUnwrapKey", jsFunc(fckUnwrapKeyJS))

	// Drive share AES-GCM (matches Web Crypto API format)
	vpCrypto.Set("aesGcmEncryptShare", jsFunc(aesGcmEncryptShareJS))
	vpCrypto.Set("aesGcmDecryptShare", jsFunc(aesGcmDecryptShareJS))
	vpCrypto.Set("pbkdf2DeriveShareKey", jsFunc(pbkdf2DeriveShareKeyJS))
	vpCrypto.Set("generateRandomBytes", jsFunc(generateRandomBytesJS))

	// Key Transparency
	vpCrypto.Set("verifyKTProof", jsFunc(verifyKTProof))
	vpCrypto.Set("verifyMyKey", jsFunc(verifyMyKey))

	// PGP (OpenPGP interoperability)
	vpCrypto.Set("pgpGenerateKey", jsFunc(pgpGenerateKey))
	vpCrypto.Set("pgpEncryptMessage", jsFunc(pgpEncryptMessageJS))
	vpCrypto.Set("pgpDecryptMessage", jsFunc(pgpDecryptMessageJS))
	vpCrypto.Set("pgpSignMessage", jsFunc(pgpSignMessageJS))
	vpCrypto.Set("pgpVerifySignature", jsFunc(pgpVerifySignatureJS))
	vpCrypto.Set("pgpGetFingerprint", jsFunc(pgpGetFingerprintJS))
	vpCrypto.Set("pgpExportPublicKey", jsFunc(pgpExportPublicKeyJS))

	// OPAQUE
	vpCrypto.Set("opaqueRegistrationStart", jsFunc(opaqueRegistrationStart))
	vpCrypto.Set("opaqueRegistrationFinish", jsFunc(opaqueRegistrationFinish))
	vpCrypto.Set("opaqueRecoveryRegistrationFinish", jsFunc(opaqueRecoveryRegistrationFinish))
	vpCrypto.Set("opaqueLoginStart", jsFunc(opaqueLoginStart))
	vpCrypto.Set("opaqueLoginFinish", jsFunc(opaqueLoginFinish))

	// Password validation (so frontend can check before registration).
	vpCrypto.Set("validatePassword", jsFunc(validatePasswordJS))

	// Blind-signature primitives (Fake ID mint + ratchet flows).
	vpCrypto.Set("blindMessage", jsFunc(blindMessageJS))
	vpCrypto.Set("unblindSignature", jsFunc(unblindSignatureJS))
	vpCrypto.Set("verifyBlindSignature", jsFunc(verifyBlindSignatureJS))

	js.Global().Set("vpCrypto", vpCrypto)

	// Start periodic cleanup of expired OPAQUE client entries.
	go cleanupExpiredClients()

	// Signal that the module is ready.
	js.Global().Get("document").Call("dispatchEvent",
		js.Global().Get("CustomEvent").New("vpCryptoReady"))

	// Block forever so the WASM module stays alive.
	select {}
}
