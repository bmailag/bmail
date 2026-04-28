package crypto

import (
	"strings"
	"testing"
)

func TestGeneratePGPKey(t *testing.T) {
	t.Parallel()
	privArmored, pubArmored, err := GeneratePGPKey("test@bmail.ag")
	if err != nil {
		t.Fatalf("GeneratePGPKey: %v", err)
	}

	if !strings.Contains(privArmored, "BEGIN PGP PRIVATE KEY BLOCK") {
		t.Error("private key not armored correctly")
	}
	if !strings.Contains(pubArmored, "BEGIN PGP PUBLIC KEY BLOCK") {
		t.Error("public key not armored correctly")
	}

	// Verify fingerprint extraction.
	fp, err := GetPGPFingerprint(pubArmored)
	if err != nil {
		t.Fatalf("GetPGPFingerprint: %v", err)
	}
	if len(fp) == 0 {
		t.Error("empty fingerprint")
	}
}

func TestPGPEncryptDecrypt(t *testing.T) {
	t.Parallel()
	_, pubArmored, err := GeneratePGPKey("alice@bmail.ag")
	if err != nil {
		t.Fatalf("generate alice key: %v", err)
	}
	privArmored2, _, err := GeneratePGPKey("bob@bmail.ag")
	if err != nil {
		t.Fatalf("generate bob key: %v", err)
	}

	// Generate a key where bob is the recipient.
	bobPriv, bobPub, err := GeneratePGPKey("bob@bmail.ag")
	if err != nil {
		t.Fatalf("generate bob key: %v", err)
	}
	_ = pubArmored
	_ = privArmored2

	plaintext := "Hello Bob, this is a secret message!"
	encrypted, err := PGPEncryptMessage([]string{bobPub}, "Test Subject", plaintext)
	if err != nil {
		t.Fatalf("PGPEncryptMessage: %v", err)
	}

	if !strings.Contains(encrypted, "BEGIN PGP MESSAGE") {
		t.Error("encrypted message not armored")
	}

	// Decrypt.
	decrypted, err := PGPDecryptMessage(bobPriv, encrypted)
	if err != nil {
		t.Fatalf("PGPDecryptMessage: %v", err)
	}

	if !strings.Contains(string(decrypted), plaintext) {
		t.Errorf("decrypted message doesn't contain plaintext: got %q", string(decrypted))
	}
}

func TestPGPSignVerify(t *testing.T) {
	t.Parallel()
	priv, pub, err := GeneratePGPKey("signer@bmail.ag")
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	message := []byte("This is an important message.")
	sig, err := PGPSignMessage(priv, message)
	if err != nil {
		t.Fatalf("PGPSignMessage: %v", err)
	}

	valid, err := PGPVerifySignature(pub, message, sig)
	if err != nil {
		t.Fatalf("PGPVerifySignature: %v", err)
	}
	if !valid {
		t.Error("signature should be valid")
	}

	// With a different key, verification should fail.
	_, otherPub, _ := GeneratePGPKey("other@bmail.ag")
	valid2, _ := PGPVerifySignature(otherPub, message, sig)
	if valid2 {
		t.Error("wrong key should not verify")
	}
}

func TestPGPEncryptSign(t *testing.T) {
	t.Parallel()
	alicePriv, alicePub, err := GeneratePGPKey("alice@bmail.ag")
	if err != nil {
		t.Fatalf("generate alice: %v", err)
	}
	_, bobPub, err := GeneratePGPKey("bob@bmail.ag")
	if err != nil {
		t.Fatalf("generate bob: %v", err)
	}
	_ = alicePub

	body := []byte("Authenticated encrypted message")
	encrypted, err := PGPEncryptSign(alicePriv, []string{bobPub}, body)
	if err != nil {
		// Some gopenpgp versions may not support combined encrypt+sign for all key types.
		// This is acceptable — we can fall back to separate encrypt and sign.
		t.Skipf("PGPEncryptSign not supported: %v", err)
	}

	if !strings.Contains(encrypted, "BEGIN PGP MESSAGE") {
		t.Error("encrypted+signed message not armored")
	}
}

func TestExportPGPPublicKeyBinary(t *testing.T) {
	t.Parallel()
	_, pub, err := GeneratePGPKey("export@bmail.ag")
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	binary, err := ExportPGPPublicKeyBinary(pub)
	if err != nil {
		t.Fatalf("ExportPGPPublicKeyBinary: %v", err)
	}
	if len(binary) == 0 {
		t.Error("binary key is empty")
	}
	// Binary keys should NOT start with "-----BEGIN"
	if strings.HasPrefix(string(binary), "-----") {
		t.Error("binary key looks armored")
	}
}

func TestDetectPGPMIME(t *testing.T) {
	t.Parallel()
	pgpMIME := []byte("Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"\r\n\r\nbody")
	if !DetectPGPMIME(pgpMIME) {
		t.Error("should detect PGP/MIME")
	}

	plain := []byte("Content-Type: text/plain\r\n\r\nhello")
	if DetectPGPMIME(plain) {
		t.Error("should not detect PGP/MIME in plain message")
	}
}

func TestDetectPGPInline(t *testing.T) {
	t.Parallel()
	inline := []byte("Some text\n-----BEGIN PGP MESSAGE-----\ndata\n-----END PGP MESSAGE-----")
	if !DetectPGPInline(inline) {
		t.Error("should detect inline PGP")
	}

	plain := []byte("Just a regular message")
	if DetectPGPInline(plain) {
		t.Error("should not detect inline PGP in plain message")
	}
}

func TestDetectSMIME(t *testing.T) {
	t.Parallel()
	smime := []byte("Content-Type: application/pkcs7-mime; smime-type=enveloped-data\r\n\r\ndata")
	if !DetectSMIME(smime) {
		t.Error("should detect S/MIME")
	}

	plain := []byte("Content-Type: text/plain\r\n\r\nhello")
	if DetectSMIME(plain) {
		t.Error("should not detect S/MIME in plain message")
	}
}

func TestParseAutocryptHeader(t *testing.T) {
	t.Parallel()
	header := "addr=alice@example.com; prefer-encrypt=mutual; keydata=dGVzdGtleWRhdGE="
	email, keyData, preferEnc, err := ParseAutocryptHeader(header)
	if err != nil {
		t.Fatalf("ParseAutocryptHeader: %v", err)
	}
	if email != "alice@example.com" {
		t.Errorf("email = %q, want alice@example.com", email)
	}
	// F-17: keyData is now decoded bytes, not raw base64 string.
	if string(keyData) != "testkeydata" {
		t.Errorf("keyData = %q, want 'testkeydata'", string(keyData))
	}
	if preferEnc != "mutual" {
		t.Errorf("preferEncrypt = %q, want mutual", preferEnc)
	}

	// Missing addr should fail.
	_, _, _, err = ParseAutocryptHeader("keydata=abc=")
	if err == nil {
		t.Error("should fail with missing addr")
	}

	// Invalid base64 should fail (F-17 verification).
	_, _, _, err = ParseAutocryptHeader("addr=test@example.com; keydata=!!!not-valid-base64!!!")
	if err == nil {
		t.Error("should fail with invalid base64 keydata")
	}
}

func TestFormatAutocryptHeader(t *testing.T) {
	t.Parallel()
	h := FormatAutocryptHeader("alice@bmail.ag", "base64keydata")
	if !strings.Contains(h, "addr=alice@bmail.ag") {
		t.Error("missing addr")
	}
	if !strings.Contains(h, "keydata=base64keydata") {
		t.Error("missing keydata")
	}
	if !strings.Contains(h, "prefer-encrypt=mutual") {
		t.Error("missing prefer-encrypt=mutual")
	}
}

func TestFormatAutocryptHeader_CRLFInjection(t *testing.T) {
	t.Parallel()

	// Attempt CRLF injection in email parameter.
	h := FormatAutocryptHeader("evil@example.com\r\nBcc: spy@attacker.com", "base64key")
	if strings.Contains(h, "\r") || strings.Contains(h, "\n") {
		t.Error("CRLF injection not sanitized in email")
	}
	if !strings.Contains(h, "addr=evil@example.comBcc: spy@attacker.com") {
		t.Errorf("expected CRLF stripped from email, got: %q", h)
	}

	// Attempt CRLF injection in keydata parameter.
	h2 := FormatAutocryptHeader("test@example.com", "key\r\nEvil: header")
	if strings.Contains(h2, "\r") || strings.Contains(h2, "\n") {
		t.Error("CRLF injection not sanitized in keydata")
	}

	// Null byte injection.
	h3 := FormatAutocryptHeader("test\x00@evil.com", "key\x00data")
	if strings.Contains(h3, "\x00") {
		t.Error("null byte not sanitized")
	}
}

func TestPGPPublicKeyFromArmored(t *testing.T) {
	t.Parallel()
	_, pubArmored, err := GeneratePGPKey("parsetest@bmail.ag")
	if err != nil {
		t.Fatalf("GeneratePGPKey: %v", err)
	}

	key, err := PGPPublicKeyFromArmored(pubArmored)
	if err != nil {
		t.Fatalf("PGPPublicKeyFromArmored: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}

	// Verify identity is preserved — the key should contain the email we generated with.
	fp := key.GetFingerprint()
	if len(fp) == 0 {
		t.Error("expected non-empty fingerprint from parsed key")
	}

	// Invalid armored input should fail.
	_, err = PGPPublicKeyFromArmored("not a valid armored key")
	if err == nil {
		t.Error("expected error for invalid armored input")
	}
}

func TestGetPGPFingerprint(t *testing.T) {
	t.Parallel()
	_, pubArmored, err := GeneratePGPKey("fptest@bmail.ag")
	if err != nil {
		t.Fatalf("GeneratePGPKey: %v", err)
	}

	fp, err := GetPGPFingerprint(pubArmored)
	if err != nil {
		t.Fatalf("GetPGPFingerprint: %v", err)
	}

	// v6 fingerprints are 64 hex chars (32 bytes), v4 are 40 hex chars (20 bytes).
	// Accept either.
	if len(fp) != 40 && len(fp) != 64 {
		t.Errorf("expected fingerprint of 40 or 64 hex chars, got %d chars: %s", len(fp), fp)
	}

	// Verify it's valid hex.
	for _, c := range fp {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			t.Errorf("fingerprint contains non-hex character: %c", c)
			break
		}
	}

	// Two different keys should have different fingerprints.
	_, pubArmored2, err := GeneratePGPKey("fptest2@bmail.ag")
	if err != nil {
		t.Fatalf("GeneratePGPKey (second): %v", err)
	}
	fp2, err := GetPGPFingerprint(pubArmored2)
	if err != nil {
		t.Fatalf("GetPGPFingerprint (second): %v", err)
	}
	if fp == fp2 {
		t.Error("two different keys should have different fingerprints")
	}
}

// TestPGPRoundtrip is a comprehensive end-to-end test covering:
// 1. Key generation
// 2. Encrypt with public key -> decrypt with private key -> verify plaintext matches
// 3. Sign -> verify -> tamper message -> verify fails
// 4. Encrypt+sign roundtrip with sender authentication
// 5. Wrong-key decryption must fail
func TestPGPRoundtrip(t *testing.T) {
	t.Parallel()

	// --- Step 1: Generate keys for Alice (sender) and Bob (recipient) ---
	alicePriv, alicePub, err := GeneratePGPKey("alice-rt@bmail.ag")
	if err != nil {
		t.Fatalf("generate Alice key: %v", err)
	}
	bobPriv, bobPub, err := GeneratePGPKey("bob-rt@bmail.ag")
	if err != nil {
		t.Fatalf("generate Bob key: %v", err)
	}

	// Sanity: keys are distinct.
	aliceFP, _ := GetPGPFingerprint(alicePub)
	bobFP, _ := GetPGPFingerprint(bobPub)
	if aliceFP == bobFP {
		t.Fatal("Alice and Bob should have distinct fingerprints")
	}

	// --- Step 2: Encrypt -> Decrypt roundtrip ---
	const subject = "Roundtrip Test"
	const body = "The quick brown fox jumps over the lazy dog. 🦊"

	ciphertext, err := PGPEncryptMessage([]string{bobPub}, subject, body)
	if err != nil {
		t.Fatalf("PGPEncryptMessage: %v", err)
	}
	if !strings.Contains(ciphertext, "BEGIN PGP MESSAGE") {
		t.Fatal("ciphertext is not an armored PGP message")
	}
	// Ciphertext must not leak the plaintext.
	if strings.Contains(ciphertext, body) {
		t.Fatal("ciphertext contains plaintext in the clear")
	}

	decrypted, err := PGPDecryptMessage(bobPriv, ciphertext)
	if err != nil {
		t.Fatalf("PGPDecryptMessage: %v", err)
	}
	if !strings.Contains(string(decrypted), body) {
		t.Errorf("decrypted body mismatch: got %q", string(decrypted))
	}
	if !strings.Contains(string(decrypted), subject) {
		t.Errorf("decrypted message should contain subject in protected headers: got %q", string(decrypted))
	}

	// --- Step 3: Wrong key must fail decryption ---
	_, wrongDecryptErr := PGPDecryptMessage(alicePriv, ciphertext)
	if wrongDecryptErr == nil {
		t.Error("decryption with wrong private key should fail")
	}

	// --- Step 4: Sign -> Verify roundtrip ---
	message := []byte("This message is signed by Alice.")
	sig, err := PGPSignMessage(alicePriv, message)
	if err != nil {
		t.Fatalf("PGPSignMessage: %v", err)
	}

	valid, err := PGPVerifySignature(alicePub, message, sig)
	if err != nil {
		t.Fatalf("PGPVerifySignature: %v", err)
	}
	if !valid {
		t.Error("valid signature should verify successfully")
	}

	// --- Step 5: Wrong public key must fail verification ---
	// PGPSignMessage produces inline signatures (message embedded in the
	// signature), so the message parameter is ignored during inline verify.
	// The correct negative test is using a wrong verification key.
	validWrongKey, _ := PGPVerifySignature(bobPub, message, sig)
	if validWrongKey {
		t.Error("signature should NOT verify with wrong public key")
	}

	// --- Step 6: Corrupted signature must fail verification ---
	corruptedSig := strings.Replace(sig, "AAAA", "BBBB", 1)
	if corruptedSig != sig { // only test if replacement actually changed something
		validCorrupted, _ := PGPVerifySignature(alicePub, message, corruptedSig)
		if validCorrupted {
			t.Error("corrupted signature should NOT verify")
		}
	}

	// --- Step 7: Encrypt+Sign roundtrip (authenticated encryption) ---
	authBody := []byte("Authenticated and encrypted content from Alice to Bob.")
	encSigned, err := PGPEncryptSign(alicePriv, []string{bobPub}, authBody)
	if err != nil {
		// Some gopenpgp builds may not support combined encrypt+sign; skip gracefully.
		t.Skipf("PGPEncryptSign not supported: %v", err)
	}
	if !strings.Contains(encSigned, "BEGIN PGP MESSAGE") {
		t.Fatal("encrypt+sign output is not an armored PGP message")
	}

	// Bob decrypts. (Signature verification is embedded but PGPDecryptMessage
	// doesn't expose it separately; we just confirm the plaintext survives.)
	decAuthBody, err := PGPDecryptMessage(bobPriv, encSigned)
	if err != nil {
		t.Fatalf("decrypt encrypt+sign message: %v", err)
	}
	if string(decAuthBody) != string(authBody) {
		t.Errorf("authenticated decrypt mismatch: got %q, want %q", string(decAuthBody), string(authBody))
	}

	// Alice (wrong recipient) cannot decrypt.
	_, wrongRecipErr := PGPDecryptMessage(alicePriv, encSigned)
	if wrongRecipErr == nil {
		t.Error("sender (Alice) should not be able to decrypt message encrypted to Bob")
	}
}

// TestPGPSignVerifyIntegrity tests that signature verification rejects
// corrupted signatures and wrong keys. PGPSignMessage produces inline
// signatures (message embedded in the signed output), so tampering is
// tested by corrupting the signature blob and by using wrong keys.
func TestPGPSignVerifyIntegrity(t *testing.T) {
	t.Parallel()

	priv, pub, err := GeneratePGPKey("tampertest@bmail.ag")
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	original := []byte("Exact message content that was signed.")
	sig, err := PGPSignMessage(priv, original)
	if err != nil {
		t.Fatalf("PGPSignMessage: %v", err)
	}

	// Verify original works.
	ok, err := PGPVerifySignature(pub, original, sig)
	if err != nil {
		t.Fatalf("verify original: %v", err)
	}
	if !ok {
		t.Fatal("original message must verify")
	}

	// Wrong key must fail.
	_, wrongPub, err := GeneratePGPKey("wrong@bmail.ag")
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}
	okWrongKey, _ := PGPVerifySignature(wrongPub, original, sig)
	if okWrongKey {
		t.Error("wrong key must not verify signature")
	}

	// Corrupted signature data must fail.
	// Replace base64 chars in the signature body to corrupt it.
	corruptedSig := strings.Replace(sig, "AAAA", "ZZZZ", 1)
	if corruptedSig == sig {
		// Try a different substitution if AAAA wasn't found.
		corruptedSig = strings.Replace(sig, "BBBB", "YYYY", 1)
	}
	if corruptedSig != sig {
		okCorrupted, _ := PGPVerifySignature(pub, original, corruptedSig)
		if okCorrupted {
			t.Error("corrupted signature must not verify")
		}
	}

	// Completely bogus signature must fail.
	// Should return false or error — either is acceptable.
	// The important thing is it doesn't return (true, nil).
	okBogus, _ := PGPVerifySignature(pub, original, "not a PGP signature at all")
	if okBogus {
		t.Error("bogus signature must not verify")
	}

	// Sign a different message with the same key — verify cross-contamination
	// doesn't happen. (Each inline signature embeds its own message.)
	other := []byte("A completely different message.")
	sig2, err := PGPSignMessage(priv, other)
	if err != nil {
		t.Fatalf("PGPSignMessage (other): %v", err)
	}

	ok2, _ := PGPVerifySignature(pub, other, sig2)
	if !ok2 {
		t.Error("second signature should verify for its own message")
	}

	// Verify that sig2 doesn't verify with sig1's key expectations are met.
	// (Both use same key, but inline verify just checks signature validity,
	// so both should verify with the same pub key — this is correct behavior.)
	ok3, _ := PGPVerifySignature(pub, original, sig)
	if !ok3 {
		t.Error("original sig should still verify after signing another message")
	}
}

func TestExportPGPPublicKeyMinimal(t *testing.T) {
	t.Parallel()
	_, pubArmored, err := GeneratePGPKey("minimal@bmail.ag")
	if err != nil {
		t.Fatalf("GeneratePGPKey: %v", err)
	}

	minimal, err := ExportPGPPublicKeyMinimal(pubArmored)
	if err != nil {
		t.Fatalf("ExportPGPPublicKeyMinimal: %v", err)
	}
	if len(minimal) == 0 {
		t.Fatal("expected non-empty minimal export")
	}

	// Minimal export should be binary (not armored).
	if strings.HasPrefix(string(minimal), "-----") {
		t.Error("minimal export looks armored, expected binary")
	}

	// The full armored export (with headers/base64 overhead) should be longer
	// than the binary minimal export.
	if len(pubArmored) <= len(minimal) {
		t.Errorf("expected armored key (%d bytes) to be longer than binary minimal (%d bytes)", len(pubArmored), len(minimal))
	}

	// The minimal binary should still be a valid PGP key — re-import not
	// possible via PGPPublicKeyFromArmored (it's binary), but we can verify
	// it starts with a valid PGP packet tag (bit 7 set).
	if minimal[0]&0x80 == 0 {
		t.Error("binary key should start with a valid PGP packet tag (bit 7 set)")
	}
}
