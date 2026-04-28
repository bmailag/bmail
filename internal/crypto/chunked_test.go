package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestEncryptDecryptChunkedRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	// Test various sizes: empty, smaller than chunk, exactly one chunk, multi-chunk, non-aligned
	sizes := []int{0, 100, DefaultChunkSize, DefaultChunkSize * 3, DefaultChunkSize*2 + 1234}
	for _, size := range sizes {
		plaintext := make([]byte, size)
		if size > 0 {
			rand.Read(plaintext)
		}

		blob, err := EncryptChunked(key, plaintext, DefaultChunkSize)
		if err != nil {
			t.Fatalf("EncryptChunked(%d bytes): %v", size, err)
		}

		decrypted, err := DecryptChunked(key, blob, DefaultChunkSize)
		if err != nil {
			t.Fatalf("DecryptChunked(%d bytes): %v", size, err)
		}

		if !bytes.Equal(plaintext, decrypted) {
			t.Fatalf("round-trip failed for %d bytes: plaintext != decrypted", size)
		}
	}
}

func TestDecryptSingleChunk(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	// 3 chunks: 64KB + 64KB + 1234 bytes
	plaintext := make([]byte, DefaultChunkSize*2+1234)
	rand.Read(plaintext)

	blob, err := EncryptChunked(key, plaintext, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	storedChunkSize := DefaultChunkSize + ChunkTagSize

	// Decrypt each chunk individually and verify it matches the corresponding plaintext range.
	numChunks := (len(plaintext) + DefaultChunkSize - 1) / DefaultChunkSize
	for i := 0; i < numChunks; i++ {
		offset := i * storedChunkSize
		end := offset + storedChunkSize
		if end > len(blob) {
			end = len(blob)
		}
		chunkData := blob[offset:end]

		decrypted, err := DecryptChunk(key, i, chunkData, DefaultChunkSize)
		if err != nil {
			t.Fatalf("DecryptChunk(%d): %v", i, err)
		}

		ptStart := i * DefaultChunkSize
		ptEnd := ptStart + DefaultChunkSize
		if ptEnd > len(plaintext) {
			ptEnd = len(plaintext)
		}
		expected := plaintext[ptStart:ptEnd]

		if !bytes.Equal(expected, decrypted) {
			t.Fatalf("chunk %d mismatch: expected %d bytes, got %d", i, len(expected), len(decrypted))
		}
	}
}

func TestChunkedBlobIndistinguishable(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	plaintext := make([]byte, 1000)
	rand.Read(plaintext)

	blob, err := EncryptChunked(key, plaintext, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	// Verify no magic bytes or identifiable header.
	if len(blob) >= 4 && string(blob[:4]) == "BMv1" {
		t.Fatal("blob contains magic bytes — should be indistinguishable from random")
	}
}

func TestWrongKeyFails(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	plaintext := []byte("secret message")
	blob, err := EncryptChunked(key1, plaintext, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptChunked(key2, blob, DefaultChunkSize)
	if err == nil {
		t.Fatal("expected decryption to fail with wrong key")
	}
}

func TestChunkReorderingFails(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	plaintext := make([]byte, DefaultChunkSize*2)
	rand.Read(plaintext)

	blob, err := EncryptChunked(key, plaintext, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	storedChunkSize := DefaultChunkSize + ChunkTagSize

	// Try decrypting chunk 1's data as chunk 0 — should fail due to AAD mismatch.
	chunk1Data := blob[storedChunkSize : storedChunkSize*2]
	_, err = DecryptChunk(key, 0, chunk1Data, DefaultChunkSize)
	if err == nil {
		t.Fatal("expected chunk reordering to fail")
	}
}

func TestParseRawBlobFormat(t *testing.T) {
	tests := []struct {
		format    string
		chunked   bool
		chunkSize int
	}{
		{"XChaCha20-Poly1305", false, 0},
		{"XChaCha20-Poly1305-Chunked(65536)", true, 65536},
		{"XChaCha20-Poly1305-Chunked(262144)", true, 262144},
		{"unknown-format", false, 0},
		{"", false, 0},
	}
	for _, tt := range tests {
		chunked, cs := ParseRawBlobFormat(tt.format)
		if chunked != tt.chunked || cs != tt.chunkSize {
			t.Errorf("ParseRawBlobFormat(%q) = (%v, %d), want (%v, %d)", tt.format, chunked, cs, tt.chunked, tt.chunkSize)
		}
	}
}

func TestRawBlobFormatChunkedString(t *testing.T) {
	s := RawBlobFormatChunked(65536)
	if s != "XChaCha20-Poly1305-Chunked(65536)" {
		t.Fatalf("got %q", s)
	}
	chunked, cs := ParseRawBlobFormat(s)
	if !chunked || cs != 65536 {
		t.Fatalf("round-trip failed: chunked=%v, cs=%d", chunked, cs)
	}
}
