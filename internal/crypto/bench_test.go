package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func BenchmarkEncryptMessage(b *testing.B) {
	kp, err := GenerateX25519KeyPair()
	if err != nil {
		b.Fatal(err)
	}
	subject := []byte("Benchmark Subject")
	body := make([]byte, 4096)
	rand.Read(body)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := EncryptMessage(kp.Public, subject, body)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptMessage(b *testing.B) {
	kp, err := GenerateX25519KeyPair()
	if err != nil {
		b.Fatal(err)
	}
	subject := []byte("Benchmark Subject")
	body := make([]byte, 4096)
	rand.Read(body)

	enc, err := EncryptMessage(kp.Public, subject, body)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := DecryptMessage(kp.Private, enc)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEpochTraversal(b *testing.B) {
	const chainLen = 10
	// Build a chain of epoch keys.
	epochs := make([]*EpochKeyPair, chainLen+1)
	var err error
	for i := 0; i <= chainLen; i++ {
		epochs[i], err = GenerateEpochKey(uint64(i))
		if err != nil {
			b.Fatal(err)
		}
	}

	chain := make([]EncryptedEpochKey, chainLen)
	for i := chainLen; i > 0; i-- {
		enc, err := EncryptPreviousEpochKey(epochs[i-1].Private, uint64(i-1), epochs[i].Public)
		if err != nil {
			b.Fatal(err)
		}
		chain[chainLen-i] = *enc
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := TraverseEpochChain(chain, epochs[chainLen].Private)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHKDF(b *testing.B) {
	secret := make([]byte, 32)
	salt := make([]byte, 32)
	rand.Read(secret)
	rand.Read(salt)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := deriveKey(secret, salt, "benchmark-info")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkX25519ECDH(b *testing.B) {
	kp1, _ := ecdh.X25519().GenerateKey(rand.Reader)
	kp2, _ := ecdh.X25519().GenerateKey(rand.Reader)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := kp1.ECDH(kp2.PublicKey())
		if err != nil {
			b.Fatal(err)
		}
	}
}
