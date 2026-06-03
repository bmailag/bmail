package crypto

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"fmt"
)

// E2E private groups (ADR-012). A group has a single shared hybrid keypair
// (X25519 + ML-KEM-768). The PUBLIC key is published to KT and used to
// encrypt-to-group; the PRIVATE key is serialized into a "group secret blob"
// and wrapped (KEM-encapsulated + AEAD-sealed) to each member's published key
// using the same envelope primitive as message-key wrapping. The server never
// sees the blob or the private key.

// GroupSecretBlobSize is the serialized group private key: X25519 private (32)
// followed by the ML-KEM-768 decapsulation-key seed (64).
const GroupSecretBlobSize = 32 + MLKEMDecapsulationKeySize

// GroupKeypair is a freshly generated group keypair. Public halves go to KT +
// storage; Secret is the blob wrapped to each member.
type GroupKeypair struct {
	X25519Pub []byte // 32 bytes
	KEMPub    []byte // 1184 bytes (ML-KEM-768 encapsulation key)
	Secret    []byte // GroupSecretBlobSize bytes (private material)
}

// GenerateGroupKeypair generates a new hybrid group keypair.
func GenerateGroupKeypair() (*GroupKeypair, error) {
	enc, err := GenerateX25519KeyPair()
	if err != nil {
		return nil, fmt.Errorf("group x25519 keygen: %w", err)
	}
	kem, err := GenerateMLKEMKeyPair()
	if err != nil {
		return nil, fmt.Errorf("group ML-KEM keygen: %w", err)
	}
	secret, err := MarshalGroupSecret(enc.Private.Bytes(), kem.DecapsulationKey.Bytes())
	if err != nil {
		return nil, err
	}
	return &GroupKeypair{
		X25519Pub: enc.Public.Bytes(),
		KEMPub:    kem.EncapsulationKey.Bytes(),
		Secret:    secret,
	}, nil
}

// MarshalGroupSecret serializes group private material into the wrap blob.
func MarshalGroupSecret(x25519Priv, kemSeed []byte) ([]byte, error) {
	if len(x25519Priv) != 32 {
		return nil, fmt.Errorf("group secret: x25519 private must be 32 bytes, got %d", len(x25519Priv))
	}
	if len(kemSeed) != MLKEMDecapsulationKeySize {
		return nil, fmt.Errorf("group secret: kem seed must be %d bytes, got %d", MLKEMDecapsulationKeySize, len(kemSeed))
	}
	out := make([]byte, 0, GroupSecretBlobSize)
	out = append(out, x25519Priv...)
	out = append(out, kemSeed...)
	return out, nil
}

// UnmarshalGroupSecret splits a group secret blob back into its components.
// The returned slices alias blob; copy if you need to retain them.
func UnmarshalGroupSecret(blob []byte) (x25519Priv, kemSeed []byte, err error) {
	if len(blob) != GroupSecretBlobSize {
		return nil, nil, fmt.Errorf("group secret blob must be %d bytes, got %d", GroupSecretBlobSize, len(blob))
	}
	return blob[:32], blob[32:], nil
}

// WrapGroupSecret wraps the group secret blob to a member's published hybrid key
// (X25519 + optional ML-KEM-768 encapsulation key). Returns the envelope key
// (stored as kem_output) and the AEAD-sealed blob (stored as wrapped_private_key).
// When memberKemEK is empty, a classical X25519-only envelope is produced.
func WrapGroupSecret(memberX25519Pub, memberKemEK, secret []byte) (kemOutput, wrapped []byte, err error) {
	pub, err := ecdh.X25519().NewPublicKey(memberX25519Pub)
	if err != nil {
		return nil, nil, fmt.Errorf("parse member x25519 public key: %w", err)
	}
	var ek *mlkem.EncapsulationKey768
	if len(memberKemEK) > 0 {
		ek, err = MLKEMEncapsulationKeyFromBytes(memberKemEK)
		if err != nil {
			return nil, nil, err
		}
	}
	return WrapEnvelope(pub, ek, secret)
}

// UnwrapGroupSecret recovers the group secret blob using the member's own
// private keys. myKemSeed is the member's ML-KEM-768 decapsulation-key seed
// (may be empty for a classical envelope).
func UnwrapGroupSecret(myX25519Priv, myKemSeed, kemOutput, wrapped []byte) ([]byte, error) {
	priv, err := ecdh.X25519().NewPrivateKey(myX25519Priv)
	if err != nil {
		return nil, fmt.Errorf("parse member x25519 private key: %w", err)
	}
	var dk *mlkem.DecapsulationKey768
	if len(myKemSeed) > 0 {
		dk, err = MLKEMDecapsulationKeyFromBytes(myKemSeed)
		if err != nil {
			return nil, err
		}
	}
	return UnwrapEnvelope(priv, dk, kemOutput, wrapped)
}
