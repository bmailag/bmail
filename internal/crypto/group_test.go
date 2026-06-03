package crypto

import (
	"bytes"
	"testing"
)

func TestGroupKeypairWrapUnwrapHybrid(t *testing.T) {
	// Group keypair.
	g, err := GenerateGroupKeypair()
	if err != nil {
		t.Fatalf("GenerateGroupKeypair: %v", err)
	}
	if len(g.X25519Pub) != 32 || len(g.KEMPub) != MLKEMEncapsulationKeySize || len(g.Secret) != GroupSecretBlobSize {
		t.Fatalf("unexpected sizes: x25519=%d kem=%d secret=%d", len(g.X25519Pub), len(g.KEMPub), len(g.Secret))
	}

	// A member's hybrid keypair.
	mEnc, _ := GenerateX25519KeyPair()
	mKem, _ := GenerateMLKEMKeyPair()

	// Wrap the group secret to the member.
	kemOut, wrapped, err := WrapGroupSecret(mEnc.Public.Bytes(), mKem.EncapsulationKey.Bytes(), g.Secret)
	if err != nil {
		t.Fatalf("WrapGroupSecret: %v", err)
	}

	// Member unwraps with their own private keys.
	got, err := UnwrapGroupSecret(mEnc.Private.Bytes(), mKem.DecapsulationKey.Bytes(), kemOut, wrapped)
	if err != nil {
		t.Fatalf("UnwrapGroupSecret: %v", err)
	}
	if !bytes.Equal(got, g.Secret) {
		t.Fatal("unwrapped group secret does not match original")
	}

	// The recovered blob splits into the group's actual private material.
	x25519Priv, kemSeed, err := UnmarshalGroupSecret(got)
	if err != nil {
		t.Fatalf("UnmarshalGroupSecret: %v", err)
	}
	if len(x25519Priv) != 32 || len(kemSeed) != MLKEMDecapsulationKeySize {
		t.Fatalf("bad split: x25519=%d kem=%d", len(x25519Priv), len(kemSeed))
	}
}

func TestGroupSecretWrongKeyFails(t *testing.T) {
	g, _ := GenerateGroupKeypair()
	mEnc, _ := GenerateX25519KeyPair()
	mKem, _ := GenerateMLKEMKeyPair()
	kemOut, wrapped, err := WrapGroupSecret(mEnc.Public.Bytes(), mKem.EncapsulationKey.Bytes(), g.Secret)
	if err != nil {
		t.Fatal(err)
	}

	// A different member's keys must NOT unwrap it.
	other, _ := GenerateX25519KeyPair()
	otherKem, _ := GenerateMLKEMKeyPair()
	if _, err := UnwrapGroupSecret(other.Private.Bytes(), otherKem.DecapsulationKey.Bytes(), kemOut, wrapped); err == nil {
		t.Fatal("unwrap with wrong key should fail")
	}
}

func TestGroupSecretClassicalEnvelope(t *testing.T) {
	// Without a KEM key, the envelope is classical X25519-only and still round-trips.
	g, _ := GenerateGroupKeypair()
	mEnc, _ := GenerateX25519KeyPair()
	kemOut, wrapped, err := WrapGroupSecret(mEnc.Public.Bytes(), nil, g.Secret)
	if err != nil {
		t.Fatalf("WrapGroupSecret(classical): %v", err)
	}
	got, err := UnwrapGroupSecret(mEnc.Private.Bytes(), nil, kemOut, wrapped)
	if err != nil {
		t.Fatalf("UnwrapGroupSecret(classical): %v", err)
	}
	if !bytes.Equal(got, g.Secret) {
		t.Fatal("classical envelope round-trip mismatch")
	}
}

func TestMarshalGroupSecretValidation(t *testing.T) {
	if _, err := MarshalGroupSecret(make([]byte, 31), make([]byte, MLKEMDecapsulationKeySize)); err == nil {
		t.Error("expected error for short x25519 key")
	}
	if _, err := MarshalGroupSecret(make([]byte, 32), make([]byte, 10)); err == nil {
		t.Error("expected error for bad kem seed length")
	}
	if _, _, err := UnmarshalGroupSecret(make([]byte, 10)); err == nil {
		t.Error("expected error for short blob")
	}
}
