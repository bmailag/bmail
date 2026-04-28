//go:build js && wasm

package main

import (
	"crypto/ed25519"
	"fmt"
	"syscall/js"

	"github.com/bmailag/bmail/internal/crypto"
)

// ── Signing ─────────────────────────────────────────────────

func sign(args []js.Value) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("sign requires 2 args: message, privateKey")
	}
	message := []byte(args[0].String())
	privKeyBytes, err := unb64(args[1].String())
	if err != nil {
		return nil, fmt.Errorf("decode privateKey: %w", err)
	}
	defer crypto.ZeroBytes(privKeyBytes)
	if len(privKeyBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key length: %d", len(privKeyBytes))
	}
	sig := ed25519.Sign(ed25519.PrivateKey(privKeyBytes), message)
	return b64(sig), nil
}

func verify(args []js.Value) (interface{}, error) {
	if len(args) < 3 {
		return nil, fmt.Errorf("verify requires 3 args: message, signature, publicKey")
	}
	message := []byte(args[0].String())
	sigBytes, err := unb64(args[1].String())
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	pubKeyBytes, err := unb64(args[2].String())
	if err != nil {
		return nil, fmt.Errorf("decode publicKey: %w", err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key length: %d", len(pubKeyBytes))
	}
	return ed25519.Verify(ed25519.PublicKey(pubKeyBytes), message, sigBytes), nil
}
