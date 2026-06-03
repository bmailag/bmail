//go:build js && wasm

package main

import (
	"fmt"
	"syscall/js"

	"github.com/bmailag/bmail/internal/crypto"
)

// E2E private groups (ADR-012). Thin bindings over internal/crypto's group
// helpers: generate a group hybrid keypair, and wrap/unwrap the group secret
// blob to/from a member's published (KT-verified) key. The group private key
// never leaves the client unwrapped.

// generateGroupKeypair generates a fresh hybrid group keypair.
// Returns {public_x25519, public_kem, secret} (all base64). public_* go to KT +
// the server; secret is wrapped per-member via wrapGroupSecret and must NEVER be
// sent to the server in the clear.
func generateGroupKeypair(_ []js.Value) (interface{}, error) {
	g, err := crypto.GenerateGroupKeypair()
	if err != nil {
		return nil, err
	}
	return toJSObject(map[string]interface{}{
		"public_x25519": b64(g.X25519Pub),
		"public_kem":    b64(g.KEMPub),
		"secret":        b64(g.Secret),
	}), nil
}

// wrapGroupSecret wraps the group secret blob to a member's published key.
// Args: memberX25519PubB64, memberKemEKB64 (may be ""), secretB64.
// Returns {kem_output, wrapped_private_key} (base64) for storage on the member row.
func wrapGroupSecret(args []js.Value) (interface{}, error) {
	if len(args) < 3 {
		return nil, fmt.Errorf("wrapGroupSecret requires 3 args: memberX25519Pub, memberKemEK, secret")
	}
	memberPub, err := unb64(args[0].String())
	if err != nil {
		return nil, fmt.Errorf("decode member x25519 pub: %w", err)
	}
	var memberKemEK []byte
	if s := args[1].String(); s != "" {
		if memberKemEK, err = unb64(s); err != nil {
			return nil, fmt.Errorf("decode member kem ek: %w", err)
		}
	}
	secret, err := unb64(args[2].String())
	if err != nil {
		return nil, fmt.Errorf("decode secret: %w", err)
	}
	defer crypto.ZeroBytes(secret)

	kemOut, wrapped, err := crypto.WrapGroupSecret(memberPub, memberKemEK, secret)
	if err != nil {
		return nil, fmt.Errorf("wrap group secret: %w", err)
	}
	return toJSObject(map[string]interface{}{
		"kem_output":          b64(kemOut),
		"wrapped_private_key": b64(wrapped),
	}), nil
}

// unwrapGroupSecret recovers the group secret blob using the member's own keys.
// Args: myX25519PrivB64, myKemSeedB64 (may be ""), kemOutputB64, wrappedB64.
// Returns the group secret blob (base64) — cache it to encrypt-to-group / decrypt.
func unwrapGroupSecret(args []js.Value) (interface{}, error) {
	if len(args) < 4 {
		return nil, fmt.Errorf("unwrapGroupSecret requires 4 args: myX25519Priv, myKemSeed, kemOutput, wrapped")
	}
	myPriv, err := unb64(args[0].String())
	if err != nil {
		return nil, fmt.Errorf("decode my x25519 priv: %w", err)
	}
	defer crypto.ZeroBytes(myPriv)
	var myKemSeed []byte
	if s := args[1].String(); s != "" {
		if myKemSeed, err = unb64(s); err != nil {
			return nil, fmt.Errorf("decode my kem seed: %w", err)
		}
		defer crypto.ZeroBytes(myKemSeed)
	}
	kemOut, err := unb64(args[2].String())
	if err != nil {
		return nil, fmt.Errorf("decode kem_output: %w", err)
	}
	wrapped, err := unb64(args[3].String())
	if err != nil {
		return nil, fmt.Errorf("decode wrapped_private_key: %w", err)
	}

	secret, err := crypto.UnwrapGroupSecret(myPriv, myKemSeed, kemOut, wrapped)
	if err != nil {
		return nil, fmt.Errorf("unwrap group secret: %w", err)
	}
	return b64(secret), nil
}
