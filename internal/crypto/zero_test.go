package crypto

import (
	"crypto/rand"
	"testing"
)

func TestZeroBytesZeroesSlice(t *testing.T) {
	t.Parallel()
	data := []byte{0x41, 0x42, 0x43, 0x44, 0x45}
	ZeroBytes(data)
	for i, b := range data {
		if b != 0 {
			t.Fatalf("byte %d not zeroed: got 0x%02x", i, b)
		}
	}
}

func TestZeroBytesEmptySlice(t *testing.T) {
	t.Parallel()
	// Should not panic on empty slice.
	data := []byte{}
	ZeroBytes(data)
	if len(data) != 0 {
		t.Fatal("expected empty slice to remain empty")
	}
}

func TestZeroBytesNilSlice(t *testing.T) {
	t.Parallel()
	// Should not panic on nil slice.
	var data []byte
	ZeroBytes(data)
	if data != nil {
		t.Fatal("expected nil slice to remain nil")
	}
}

func TestZeroBytesLargeSlice(t *testing.T) {
	t.Parallel()
	data := make([]byte, 4096)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	// Verify at least some bytes are non-zero before zeroing.
	allZero := true
	for _, b := range data {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("random data should not be all zeros")
	}

	ZeroBytes(data)
	for i, b := range data {
		if b != 0 {
			t.Fatalf("byte %d not zeroed in large slice: got 0x%02x", i, b)
		}
	}
}

func TestZeroBytesSingleByte(t *testing.T) {
	t.Parallel()
	data := []byte{0xFF}
	ZeroBytes(data)
	if data[0] != 0 {
		t.Fatalf("single byte not zeroed: got 0x%02x", data[0])
	}
}

func TestZeroBytesDoesNotAffectCapacity(t *testing.T) {
	t.Parallel()
	data := make([]byte, 8, 16)
	for i := range data {
		data[i] = 0xAA
	}
	ZeroBytes(data)
	if len(data) != 8 {
		t.Fatalf("expected len 8, got %d", len(data))
	}
	if cap(data) != 16 {
		t.Fatalf("expected cap 16, got %d", cap(data))
	}
	for i, b := range data {
		if b != 0 {
			t.Fatalf("byte %d not zeroed: got 0x%02x", i, b)
		}
	}
}
