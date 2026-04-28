package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"testing"
)

func mustX25519(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustMLKEM(t *testing.T) *mlkem.DecapsulationKey768 {
	t.Helper()
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	return dk
}

func TestHybridWrapUnwrap_Roundtrip(t *testing.T) {
	x25519Priv := mustX25519(t)
	kemDK := mustMLKEM(t)
	kemEK := kemDK.EncapsulationKey()

	messageKey := make([]byte, 32)
	rand.Read(messageKey)

	envKey, encMK, err := hybridWrap(x25519Priv.PublicKey(), kemEK, messageKey)
	if err != nil {
		t.Fatalf("hybridWrap: %v", err)
	}

	if len(envKey) != HybridEnvelopeKeySize {
		t.Fatalf("envelope key size: got %d, want %d", len(envKey), HybridEnvelopeKeySize)
	}
	if envKey[0] != EnvelopeVersionHybrid {
		t.Fatalf("version byte: got 0x%02x, want 0x%02x", envKey[0], EnvelopeVersionHybrid)
	}

	recovered, err := hybridUnwrap(x25519Priv, kemDK, envKey, encMK)
	if err != nil {
		t.Fatalf("hybridUnwrap: %v", err)
	}
	if !bytes.Equal(messageKey, recovered) {
		t.Fatal("recovered message key does not match original")
	}
}

func TestUnwrapEnvelope_Classical(t *testing.T) {
	x25519Priv := mustX25519(t)
	messageKey := make([]byte, 32)
	rand.Read(messageKey)

	envKey, encMK, err := classicalWrap(x25519Priv.PublicKey(), messageKey)
	if err != nil {
		t.Fatalf("classicalWrap: %v", err)
	}

	if len(envKey) != 32 {
		t.Fatalf("classical envelope key size: got %d, want 32", len(envKey))
	}

	// Unwrap without KEM DK — should succeed for classical.
	recovered, err := unwrapEnvelope(x25519Priv, nil, envKey, encMK)
	if err != nil {
		t.Fatalf("unwrapEnvelope (classical, no KEM): %v", err)
	}
	if !bytes.Equal(messageKey, recovered) {
		t.Fatal("recovered message key does not match")
	}

	// Unwrap with a KEM DK — should also succeed (KEM DK is ignored for classical).
	kemDK := mustMLKEM(t)
	recovered2, err := unwrapEnvelope(x25519Priv, kemDK, envKey, encMK)
	if err != nil {
		t.Fatalf("unwrapEnvelope (classical, with KEM): %v", err)
	}
	if !bytes.Equal(messageKey, recovered2) {
		t.Fatal("recovered message key does not match (with KEM DK)")
	}
}

func TestUnwrapEnvelope_Hybrid(t *testing.T) {
	x25519Priv := mustX25519(t)
	kemDK := mustMLKEM(t)
	kemEK := kemDK.EncapsulationKey()
	messageKey := make([]byte, 32)
	rand.Read(messageKey)

	envKey, encMK, err := hybridWrap(x25519Priv.PublicKey(), kemEK, messageKey)
	if err != nil {
		t.Fatalf("hybridWrap: %v", err)
	}

	recovered, err := unwrapEnvelope(x25519Priv, kemDK, envKey, encMK)
	if err != nil {
		t.Fatalf("unwrapEnvelope (hybrid): %v", err)
	}
	if !bytes.Equal(messageKey, recovered) {
		t.Fatal("recovered message key does not match")
	}
}

func TestUnwrapEnvelope_HybridWithoutKEMDK_Fails(t *testing.T) {
	x25519Priv := mustX25519(t)
	kemDK := mustMLKEM(t)
	kemEK := kemDK.EncapsulationKey()
	messageKey := make([]byte, 32)
	rand.Read(messageKey)

	envKey, encMK, err := hybridWrap(x25519Priv.PublicKey(), kemEK, messageKey)
	if err != nil {
		t.Fatalf("hybridWrap: %v", err)
	}

	_, err = unwrapEnvelope(x25519Priv, nil, envKey, encMK)
	if err == nil {
		t.Fatal("expected error when unwrapping hybrid without KEM DK")
	}
}

func TestUnwrapEnvelope_WrongX25519Key_Fails(t *testing.T) {
	x25519Priv := mustX25519(t)
	wrongPriv := mustX25519(t)
	kemDK := mustMLKEM(t)
	kemEK := kemDK.EncapsulationKey()
	messageKey := make([]byte, 32)
	rand.Read(messageKey)

	envKey, encMK, err := hybridWrap(x25519Priv.PublicKey(), kemEK, messageKey)
	if err != nil {
		t.Fatalf("hybridWrap: %v", err)
	}

	_, err = unwrapEnvelope(wrongPriv, kemDK, envKey, encMK)
	if err == nil {
		t.Fatal("expected error with wrong X25519 private key")
	}
}

func TestUnwrapEnvelope_WrongKEMDK_Fails(t *testing.T) {
	x25519Priv := mustX25519(t)
	kemDK := mustMLKEM(t)
	wrongKEMDK := mustMLKEM(t)
	kemEK := kemDK.EncapsulationKey()
	messageKey := make([]byte, 32)
	rand.Read(messageKey)

	envKey, encMK, err := hybridWrap(x25519Priv.PublicKey(), kemEK, messageKey)
	if err != nil {
		t.Fatalf("hybridWrap: %v", err)
	}

	_, err = unwrapEnvelope(x25519Priv, wrongKEMDK, envKey, encMK)
	if err == nil {
		t.Fatal("expected error with wrong KEM decapsulation key")
	}
}

func TestWrapEnvelope_AutoSelect(t *testing.T) {
	x25519Priv := mustX25519(t)
	kemDK := mustMLKEM(t)
	kemEK := kemDK.EncapsulationKey()
	messageKey := make([]byte, 32)
	rand.Read(messageKey)

	// With KEM EK → hybrid
	envKey, encMK, err := wrapEnvelope(x25519Priv.PublicKey(), kemEK, messageKey)
	if err != nil {
		t.Fatalf("wrapEnvelope (hybrid): %v", err)
	}
	if len(envKey) != HybridEnvelopeKeySize {
		t.Fatalf("expected hybrid envelope key size %d, got %d", HybridEnvelopeKeySize, len(envKey))
	}

	recovered, err := unwrapEnvelope(x25519Priv, kemDK, envKey, encMK)
	if err != nil {
		t.Fatalf("unwrapEnvelope (hybrid): %v", err)
	}
	if !bytes.Equal(messageKey, recovered) {
		t.Fatal("hybrid roundtrip failed")
	}

	// Without KEM EK → classical
	messageKey2 := make([]byte, 32)
	rand.Read(messageKey2)
	envKey2, encMK2, err := wrapEnvelope(x25519Priv.PublicKey(), nil, messageKey2)
	if err != nil {
		t.Fatalf("wrapEnvelope (classical): %v", err)
	}
	if len(envKey2) != 32 {
		t.Fatalf("expected classical envelope key size 32, got %d", len(envKey2))
	}

	recovered2, err := unwrapEnvelope(x25519Priv, nil, envKey2, encMK2)
	if err != nil {
		t.Fatalf("unwrapEnvelope (classical): %v", err)
	}
	if !bytes.Equal(messageKey2, recovered2) {
		t.Fatal("classical roundtrip failed")
	}
}

func TestUnwrapEnvelope_InvalidLength(t *testing.T) {
	x25519Priv := mustX25519(t)
	_, err := unwrapEnvelope(x25519Priv, nil, []byte{0x02, 0x01, 0x02}, nil)
	if err == nil {
		t.Fatal("expected error for invalid envelope key length")
	}
}

func TestHybrid_TamperedEnvelopeKey_Fails(t *testing.T) {
	x25519Priv := mustX25519(t)
	kemDK := mustMLKEM(t)
	kemEK := kemDK.EncapsulationKey()
	messageKey := make([]byte, 32)
	rand.Read(messageKey)

	envKey, encMK, err := hybridWrap(x25519Priv.PublicKey(), kemEK, messageKey)
	if err != nil {
		t.Fatalf("hybridWrap: %v", err)
	}

	// Tamper with the envelope key (flip a byte in the KEM ciphertext region)
	tampered := make([]byte, len(envKey))
	copy(tampered, envKey)
	tampered[100] ^= 0xff

	_, err = unwrapEnvelope(x25519Priv, kemDK, tampered, encMK)
	if err == nil {
		t.Fatal("expected error with tampered envelope key")
	}
}

func TestHybrid_TamperedEncryptedMK_Fails(t *testing.T) {
	x25519Priv := mustX25519(t)
	kemDK := mustMLKEM(t)
	kemEK := kemDK.EncapsulationKey()
	messageKey := make([]byte, 32)
	rand.Read(messageKey)

	envKey, encMK, err := hybridWrap(x25519Priv.PublicKey(), kemEK, messageKey)
	if err != nil {
		t.Fatalf("hybridWrap: %v", err)
	}

	tampered := make([]byte, len(encMK))
	copy(tampered, encMK)
	tampered[len(tampered)-1] ^= 0xff

	_, err = unwrapEnvelope(x25519Priv, kemDK, envKey, tampered)
	if err == nil {
		t.Fatal("expected error with tampered encrypted message key")
	}
}
