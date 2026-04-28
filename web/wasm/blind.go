//go:build js && wasm

// Blind-signature primitives exposed to JavaScript for the Fake ID mint/
// ratchet flows. The server (payment enclave) never sees the unblinded
// token — blinding is done in the browser with a fresh random factor,
// the enclave signs the blinded value, the browser unblinds to obtain
// the final (token, signature) pair.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"syscall/js"

	"github.com/bmailag/bmail/internal/crypto"
)

// parsePubKeyPEM accepts either "RSA PUBLIC KEY" (PKCS#1) or "PUBLIC KEY"
// (PKIX SubjectPublicKeyInfo) PEM blocks and returns the RSA public key.
func parsePubKeyPEM(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	switch block.Type {
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	case "PUBLIC KEY":
		k, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rk, ok := k.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("PEM does not contain an RSA public key")
		}
		return rk, nil
	default:
		return nil, fmt.Errorf("unexpected PEM type %q", block.Type)
	}
}

// blindMessageJS: blindMessage(tokenHex, pubKeyPEM) → { blinded: hex, factor: hex, token: hex }
//
// Generates a fresh random 32-byte token if tokenHex is empty, blinds it with
// a random factor coprime to the modulus, and returns the blinded value plus
// the blinding factor (for later unblinding) and the plaintext token (for
// later redemption at bmail's backend).
func blindMessageJS(args []js.Value) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("blindMessage requires 2 args: tokenHex (or \"\"), publicKeyPEM")
	}
	var token []byte
	if tokenHex := args[0].String(); tokenHex != "" {
		t, err := hex.DecodeString(tokenHex)
		if err != nil {
			return nil, fmt.Errorf("decode tokenHex: %w", err)
		}
		token = t
	} else {
		token = make([]byte, 32)
		if _, err := rand.Read(token); err != nil {
			return nil, fmt.Errorf("generate random token: %w", err)
		}
	}
	pub, err := parsePubKeyPEM(args[1].String())
	if err != nil {
		return nil, fmt.Errorf("parse publicKeyPEM: %w", err)
	}
	blinded, factor, err := crypto.BlindMessage(token, pub)
	if err != nil {
		return nil, fmt.Errorf("blind: %w", err)
	}
	return toJSObject(map[string]interface{}{
		"blinded": hex.EncodeToString(blinded.Bytes()),
		"factor":  hex.EncodeToString(factor.Bytes()),
		"token":   hex.EncodeToString(token),
	}), nil
}

// unblindSignatureJS: unblindSignature(blindSigHex, factorHex, pubKeyPEM) → { signature: hex }
//
// Removes the caller's blinding factor from a blind signature returned by the
// server, producing the final RSA signature on the plaintext token.
func unblindSignatureJS(args []js.Value) (interface{}, error) {
	if len(args) < 3 {
		return nil, fmt.Errorf("unblindSignature requires 3 args: blindSigHex, factorHex, publicKeyPEM")
	}
	blindSigBytes, err := hex.DecodeString(args[0].String())
	if err != nil {
		return nil, fmt.Errorf("decode blindSigHex: %w", err)
	}
	factorBytes, err := hex.DecodeString(args[1].String())
	if err != nil {
		return nil, fmt.Errorf("decode factorHex: %w", err)
	}
	pub, err := parsePubKeyPEM(args[2].String())
	if err != nil {
		return nil, fmt.Errorf("parse publicKeyPEM: %w", err)
	}
	blindSig := new(big.Int).SetBytes(blindSigBytes)
	factor := new(big.Int).SetBytes(factorBytes)
	sig, err := crypto.UnblindSignature(blindSig, factor, pub)
	if err != nil {
		return nil, fmt.Errorf("unblind: %w", err)
	}
	return toJSObject(map[string]interface{}{
		"signature": hex.EncodeToString(sig.Bytes()),
	}), nil
}

// verifyBlindSignatureJS: verifyBlindSignature(tokenHex, sigHex, pubKeyPEM) → bool
//
// Client-side sanity check before sending a credential to the backend — if
// this fails, something went wrong locally (wrong pubkey, corrupted sig) and
// the backend would have rejected it anyway.
func verifyBlindSignatureJS(args []js.Value) (interface{}, error) {
	if len(args) < 3 {
		return nil, fmt.Errorf("verifyBlindSignature requires 3 args: tokenHex, signatureHex, publicKeyPEM")
	}
	token, err := hex.DecodeString(args[0].String())
	if err != nil {
		return nil, fmt.Errorf("decode tokenHex: %w", err)
	}
	sigBytes, err := hex.DecodeString(args[1].String())
	if err != nil {
		return nil, fmt.Errorf("decode signatureHex: %w", err)
	}
	pub, err := parsePubKeyPEM(args[2].String())
	if err != nil {
		return nil, fmt.Errorf("parse publicKeyPEM: %w", err)
	}
	sig := new(big.Int).SetBytes(sigBytes)
	return crypto.VerifySignature(token, sig, pub), nil
}
