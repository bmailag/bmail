package crypto

import (
	"bytes"
	"testing"
)

func TestGenerateMLKEMKeyPair(t *testing.T) {
	kp, err := GenerateMLKEMKeyPair()
	if err != nil {
		t.Fatalf("GenerateMLKEMKeyPair: %v", err)
	}
	if kp.EncapsulationKey == nil {
		t.Fatal("EncapsulationKey is nil")
	}
	if kp.DecapsulationKey == nil {
		t.Fatal("DecapsulationKey is nil")
	}

	ekBytes := kp.EncapsulationKey.Bytes()
	if len(ekBytes) != MLKEMEncapsulationKeySize {
		t.Fatalf("EncapsulationKey size: got %d, want %d", len(ekBytes), MLKEMEncapsulationKeySize)
	}

	dkBytes := kp.DecapsulationKey.Bytes()
	if len(dkBytes) != MLKEMDecapsulationKeySize {
		t.Fatalf("DecapsulationKey seed size: got %d, want %d", len(dkBytes), MLKEMDecapsulationKeySize)
	}
}

func TestMLKEM_EncapsulateDecapsulate(t *testing.T) {
	kp, err := GenerateMLKEMKeyPair()
	if err != nil {
		t.Fatalf("GenerateMLKEMKeyPair: %v", err)
	}

	ss, ct := kp.EncapsulationKey.Encapsulate()
	if len(ss) != MLKEMSharedSecretSize {
		t.Fatalf("shared secret size: got %d, want %d", len(ss), MLKEMSharedSecretSize)
	}
	if len(ct) != MLKEMCiphertextSize {
		t.Fatalf("ciphertext size: got %d, want %d", len(ct), MLKEMCiphertextSize)
	}

	ss2, err := kp.DecapsulationKey.Decapsulate(ct)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	if !bytes.Equal(ss, ss2) {
		t.Fatal("shared secrets do not match")
	}
}

func TestMLKEM_SeedReconstruction(t *testing.T) {
	kp, err := GenerateMLKEMKeyPair()
	if err != nil {
		t.Fatalf("GenerateMLKEMKeyPair: %v", err)
	}

	seed := kp.DecapsulationKey.Bytes()
	dk2, err := MLKEMDecapsulationKeyFromBytes(seed)
	if err != nil {
		t.Fatalf("MLKEMDecapsulationKeyFromBytes: %v", err)
	}

	// Verify seeds match
	if !bytes.Equal(kp.DecapsulationKey.Bytes(), dk2.Bytes()) {
		t.Fatal("reconstructed seed does not match original")
	}

	// Verify encapsulation keys match
	ek1 := kp.DecapsulationKey.EncapsulationKey().Bytes()
	ek2 := dk2.EncapsulationKey().Bytes()
	if !bytes.Equal(ek1, ek2) {
		t.Fatal("reconstructed encapsulation key does not match original")
	}

	// Verify cross-decapsulation works
	ss, ct := kp.EncapsulationKey.Encapsulate()
	ss2, err := dk2.Decapsulate(ct)
	if err != nil {
		t.Fatalf("cross Decapsulate: %v", err)
	}
	if !bytes.Equal(ss, ss2) {
		t.Fatal("cross-decapsulation shared secrets do not match")
	}
}

func TestMLKEM_EncapsulationKeyFromBytes(t *testing.T) {
	kp, err := GenerateMLKEMKeyPair()
	if err != nil {
		t.Fatalf("GenerateMLKEMKeyPair: %v", err)
	}

	ekBytes := kp.EncapsulationKey.Bytes()
	ek2, err := MLKEMEncapsulationKeyFromBytes(ekBytes)
	if err != nil {
		t.Fatalf("MLKEMEncapsulationKeyFromBytes: %v", err)
	}
	if !bytes.Equal(ek2.Bytes(), ekBytes) {
		t.Fatal("reconstructed encapsulation key bytes differ")
	}

	// Encapsulate with reconstructed key, decapsulate with original DK
	ss, ct := ek2.Encapsulate()
	ss2, err := kp.DecapsulationKey.Decapsulate(ct)
	if err != nil {
		t.Fatalf("Decapsulate with reconstructed EK ciphertext: %v", err)
	}
	if !bytes.Equal(ss, ss2) {
		t.Fatal("shared secrets do not match with reconstructed EK")
	}
}

func TestMLKEM_InvalidSizes(t *testing.T) {
	if _, err := MLKEMEncapsulationKeyFromBytes([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for short encapsulation key")
	}
	if _, err := MLKEMDecapsulationKeyFromBytes([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for short decapsulation key seed")
	}
	if _, err := MLKEMEncapsulationKeyFromBytes(make([]byte, MLKEMEncapsulationKeySize+1)); err == nil {
		t.Fatal("expected error for oversized encapsulation key")
	}
}

func TestMLKEM_TwoKeyPairsAreDistinct(t *testing.T) {
	kp1, _ := GenerateMLKEMKeyPair()
	kp2, _ := GenerateMLKEMKeyPair()
	if bytes.Equal(kp1.EncapsulationKey.Bytes(), kp2.EncapsulationKey.Bytes()) {
		t.Fatal("two generated key pairs have identical encapsulation keys")
	}
	if bytes.Equal(kp1.DecapsulationKey.Bytes(), kp2.DecapsulationKey.Bytes()) {
		t.Fatal("two generated key pairs have identical decapsulation key seeds")
	}
}
