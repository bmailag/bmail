package crypto

import (
	"bytes"
	"testing"
)

func TestGenerateMnemonic(t *testing.T) {
	t.Parallel()
	mnemonic, err := GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic: %v", err)
	}

	// BIP-39 24-word mnemonic
	words := splitWords(mnemonic)
	if len(words) != 24 {
		t.Fatalf("expected 24 words, got %d", len(words))
	}
}

func TestDeriveRecoveryKey_Deterministic(t *testing.T) {
	t.Parallel()
	mnemonic, err := GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic: %v", err)
	}

	key1, err := DeriveRecoveryKey(mnemonic)
	if err != nil {
		t.Fatalf("DeriveRecoveryKey (1): %v", err)
	}

	key2, err := DeriveRecoveryKey(mnemonic)
	if err != nil {
		t.Fatalf("DeriveRecoveryKey (2): %v", err)
	}

	if key1 != key2 {
		t.Fatal("same mnemonic should derive same recovery key")
	}
}

func TestDeriveRecoveryKey_DifferentMnemonics(t *testing.T) {
	t.Parallel()
	m1, err := GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic (1): %v", err)
	}
	m2, err := GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic (2): %v", err)
	}

	k1, err := DeriveRecoveryKey(m1)
	if err != nil {
		t.Fatalf("DeriveRecoveryKey (1): %v", err)
	}
	k2, err := DeriveRecoveryKey(m2)
	if err != nil {
		t.Fatalf("DeriveRecoveryKey (2): %v", err)
	}

	if k1 == k2 {
		t.Fatal("different mnemonics should derive different recovery keys")
	}
}

func TestEncryptDecryptWithRecoveryKey_Roundtrip(t *testing.T) {
	t.Parallel()
	mnemonic, err := GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic: %v", err)
	}

	recoveryKey, err := DeriveRecoveryKey(mnemonic)
	if err != nil {
		t.Fatalf("DeriveRecoveryKey: %v", err)
	}

	plaintext := []byte("This is my secret private key material that needs recovery backup")

	encrypted, err := EncryptWithRecoveryKey(plaintext, recoveryKey)
	if err != nil {
		t.Fatalf("EncryptWithRecoveryKey: %v", err)
	}

	decrypted, err := DecryptWithRecoveryKey(encrypted, recoveryKey)
	if err != nil {
		t.Fatalf("DecryptWithRecoveryKey: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("decrypted data does not match original")
	}
}

func TestDecryptWithRecoveryKey_WrongKey(t *testing.T) {
	t.Parallel()
	m1, err := GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic (1): %v", err)
	}
	m2, err := GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic (2): %v", err)
	}

	key1, err := DeriveRecoveryKey(m1)
	if err != nil {
		t.Fatalf("DeriveRecoveryKey (1): %v", err)
	}
	key2, err := DeriveRecoveryKey(m2)
	if err != nil {
		t.Fatalf("DeriveRecoveryKey (2): %v", err)
	}

	plaintext := []byte("secret data")
	encrypted, err := EncryptWithRecoveryKey(plaintext, key1)
	if err != nil {
		t.Fatalf("EncryptWithRecoveryKey: %v", err)
	}

	_, err = DecryptWithRecoveryKey(encrypted, key2)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong recovery key")
	}
}

func TestEncryptDecryptWithRecoveryKey_EmptyData(t *testing.T) {
	t.Parallel()
	mnemonic, err := GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic: %v", err)
	}

	recoveryKey, err := DeriveRecoveryKey(mnemonic)
	if err != nil {
		t.Fatalf("DeriveRecoveryKey: %v", err)
	}

	encrypted, err := EncryptWithRecoveryKey([]byte{}, recoveryKey)
	if err != nil {
		t.Fatalf("EncryptWithRecoveryKey: %v", err)
	}

	decrypted, err := DecryptWithRecoveryKey(encrypted, recoveryKey)
	if err != nil {
		t.Fatalf("DecryptWithRecoveryKey: %v", err)
	}

	if len(decrypted) != 0 {
		t.Fatalf("expected empty decrypted data, got %d bytes", len(decrypted))
	}
}

func TestDeriveRecoveryKey_InvalidMnemonic(t *testing.T) {
	t.Parallel()
	_, err := DeriveRecoveryKey("not a valid mnemonic phrase")
	if err == nil {
		t.Fatal("expected error for invalid mnemonic")
	}
}

// Audit fix F-06: V3 recovery key is user-bound.
func TestDeriveRecoveryKeyV3_UserBound(t *testing.T) {
	t.Parallel()
	mnemonic, err := GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic: %v", err)
	}

	// Same mnemonic, same user → deterministic
	k1, err := DeriveRecoveryKeyV3(mnemonic, "user@bmail.ag")
	if err != nil {
		t.Fatalf("DeriveRecoveryKeyV3: %v", err)
	}
	k2, err := DeriveRecoveryKeyV3(mnemonic, "user@bmail.ag")
	if err != nil {
		t.Fatalf("DeriveRecoveryKeyV3: %v", err)
	}
	if k1 != k2 {
		t.Fatal("same mnemonic + same user should produce same V3 key")
	}

	// Same mnemonic, different user → different key
	k3, err := DeriveRecoveryKeyV3(mnemonic, "other@bmail.ag")
	if err != nil {
		t.Fatalf("DeriveRecoveryKeyV3: %v", err)
	}
	if k1 == k3 {
		t.Fatal("same mnemonic with different users should produce different V3 keys")
	}

	// V3 differs from V2
	k2Legacy, err := DeriveRecoveryKey(mnemonic)
	if err != nil {
		t.Fatalf("DeriveRecoveryKey: %v", err)
	}
	if k1 == k2Legacy {
		t.Fatal("V3 key should differ from V2 key")
	}
}

func TestDeriveRecoveryKeyV3_EmptyUserID(t *testing.T) {
	t.Parallel()
	mnemonic, err := GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic: %v", err)
	}
	_, err = DeriveRecoveryKeyV3(mnemonic, "")
	if err == nil {
		t.Fatal("expected error for empty userID")
	}
}

// splitWords splits a string by spaces.
func splitWords(s string) []string {
	var words []string
	word := ""
	for _, c := range s {
		if c == ' ' {
			if word != "" {
				words = append(words, word)
				word = ""
			}
		} else {
			word += string(c)
		}
	}
	if word != "" {
		words = append(words, word)
	}
	return words
}
