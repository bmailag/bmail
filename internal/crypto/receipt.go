package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"sync"
	"time"
)

// senderSalt rotates daily to prevent long-term sender address tracking.
var (
	senderSalt        []byte
	senderSaltDay     int
	senderSaltLock    sync.Mutex
	senderSecretKey   []byte // server-side secret mixed into the salt
	senderSecretOnce  sync.Once
)

// InitSenderSecret sets a persistent server-side secret that is mixed into
// the daily sender hash salt. Without this secret, an attacker who knows the
// date can brute-force sender addresses from receipt hashes. The secret should
// be TEE-sealed key material (audit fix F-3).
//
// Must be called before any calls to HashSender. If not called, HashSender
// panics in production to prevent deployment without the secret.
func InitSenderSecret(secret []byte) {
	senderSaltLock.Lock()
	defer senderSaltLock.Unlock()
	senderSecretKey = make([]byte, len(secret))
	copy(senderSecretKey, secret)
	// Mark as initialized so the fallback zero-key path is skipped.
	senderSecretOnce.Do(func() {})
	// Reset cached salt so it regenerates with the new secret.
	senderSalt = nil
}

// HashSender computes a privacy-preserving, daily-rotated hash of a sender address.
// This allows receipt consumers to detect repeated senders within a day without
// exposing the raw address. The hash incorporates a server-side secret so that
// sender addresses cannot be brute-forced from receipt data alone.
func HashSender(addr string) [32]byte {
	// Ensure senderSecretKey is initialized exactly once. Production calls
	// InitSenderSecret at startup; tests get a zero key via this fallback.
	// F-15 fix: Panic in production to prevent deployment without the secret.
	senderSecretOnce.Do(func() {
		if senderSecretKey == nil {
			if os.Getenv("VP_ENV") == "production" {
				panic("SECURITY: InitSenderSecret must be called before HashSender in production")
			}
			senderSecretKey = make([]byte, 32)
		}
	})

	senderSaltLock.Lock()
	now := time.Now().UTC()
	today := now.YearDay()
	if senderSalt == nil || today != senderSaltDay {
		// Mix server secret into the daily salt so the salt is unpredictable
		// to anyone without the secret.
		h := sha256.New()
		h.Write(senderSecretKey)
		h.Write([]byte(fmt.Sprintf("sender-hash-salt:%d:%d", now.Year(), today)))
		sum := h.Sum(nil)
		senderSalt = sum
		senderSaltDay = today
	}
	salt := senderSalt
	senderSaltLock.Unlock()

	return sha256.Sum256(append(salt, []byte(addr)...))
}

// EnclaveReceipt is a signed attestation that an SGX enclave processed a message.
// Fields correspond to the receipt tuple in Paper I, Section 5, Definition 2:
// R = (mre, pk_sig, H(c), H_sender, delta_tls, delta_dkim, delta_spf, delta_dmarc, s, f, t, sigma)
type EnclaveReceipt struct {
	MessageHash      [32]byte  // SHA-256 of the original raw message
	CiphertextHash   [32]byte  // H(c): SHA-256 of the encrypted output
	SenderHash       [32]byte  // H_sender: SHA-256(sender_address || daily_salt)
	SigningPublicKey  [32]byte  // pk_sig: enclave's Ed25519 public key
	Timestamp        time.Time // t: when the enclave processed the message (F-19: uses wall clock; in SGX production, use enclave trusted time)
	EnclaveID        string    // mre: enclave identity (MRENCLAVE measurement)
	TLSVerified      bool      // delta_tls: whether inbound connection used TLS
	SPFResult        string    // delta_spf: SPF check result (pass/fail/none)
	DKIMResult       string    // delta_dkim: DKIM check result (pass/fail/none)
	DMARCResult      string    // delta_dmarc: DMARC check result (pass/fail/none)
	SpamScore        float64   // s: spam score assigned by enclave filter
	FolderAssignment string    // f: folder the message was assigned to
	Signature        []byte    // sigma: Ed25519 signature over the receipt fields
}

// receiptSigningPayload builds the canonical byte representation of a receipt
// for signing/verification. The signature field is excluded.
func receiptSigningPayload(r *EnclaveReceipt) []byte {
	var buf []byte

	buf = append(buf, 0x01) // receipt format version 1

	// MessageHash (32 bytes)
	buf = append(buf, r.MessageHash[:]...)

	// CiphertextHash (32 bytes)
	buf = append(buf, r.CiphertextHash[:]...)

	// SenderHash (32 bytes)
	buf = append(buf, r.SenderHash[:]...)

	// SigningPublicKey (32 bytes)
	buf = append(buf, r.SigningPublicKey[:]...)

	// Timestamp as Unix seconds (8 bytes, big-endian).
	// F-A9 fix: UnixNano overflows int64 after year 2262; Unix seconds are
	// safe for the foreseeable future and sufficient for receipt timestamping.
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(r.Timestamp.Unix()))
	buf = append(buf, ts...)

	// EnclaveID (length-prefixed)
	buf = appendLengthPrefixed(buf, []byte(r.EnclaveID))

	// TLSVerified (1 byte)
	if r.TLSVerified {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}

	// SPF, DKIM, DMARC results
	buf = appendLengthPrefixed(buf, []byte(r.SPFResult))
	buf = appendLengthPrefixed(buf, []byte(r.DKIMResult))
	buf = appendLengthPrefixed(buf, []byte(r.DMARCResult))

	// SpamScore as float64 bits (8 bytes, big-endian)
	score := make([]byte, 8)
	binary.BigEndian.PutUint64(score, math.Float64bits(r.SpamScore))
	buf = append(buf, score...)

	// FolderAssignment
	buf = appendLengthPrefixed(buf, []byte(r.FolderAssignment))

	return buf
}

func appendLengthPrefixed(buf, data []byte) []byte {
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(data)))
	buf = append(buf, length...)
	buf = append(buf, data...)
	return buf
}

// SignReceipt signs an EnclaveReceipt with an Ed25519 private key.
// The signature is stored in the receipt's Signature field and also returned.
func SignReceipt(receipt *EnclaveReceipt, privKey ed25519.PrivateKey) ([]byte, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key size: %d", len(privKey))
	}

	payload := receiptSigningPayload(receipt)
	sig := ed25519.Sign(privKey, payload)
	receipt.Signature = sig
	return sig, nil
}

// VerifyReceipt verifies an EnclaveReceipt's Ed25519 signature.
// F-12 fix: Rejects all-zero public keys (identity point) which would accept
// any signature. Go's ed25519.Verify (Go 1.20+) already enforces canonical
// S values per ZIP-215, providing strict signature verification.
func VerifyReceipt(receipt *EnclaveReceipt, pubKey ed25519.PublicKey) (bool, error) {
	if len(pubKey) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid Ed25519 public key size: %d", len(pubKey))
	}
	// F-12 fix: Reject the identity point (all-zero key).
	allZero := true
	for _, b := range pubKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return false, fmt.Errorf("rejected all-zero Ed25519 public key (identity point)")
	}
	if len(receipt.Signature) != ed25519.SignatureSize {
		return false, fmt.Errorf("invalid signature size: %d", len(receipt.Signature))
	}

	payload := receiptSigningPayload(receipt)
	return ed25519.Verify(pubKey, payload, receipt.Signature), nil
}
