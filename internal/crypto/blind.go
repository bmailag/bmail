// Package crypto — blind signature module.
//
// F-14 TIMING ANALYSIS: Go's math/big operations are inherently variable-time.
// This module's constant-time posture per function:
//
//   - SignBlinded (server-side, handles secret key): Protected by random
//     timing blinding — the input is re-blinded with a random factor before
//     CRT, making timing analysis of dP/dQ infeasible. Shamir fault
//     detection catches hardware/glitch faults.
//
//   - BlindMessage / UnblindSignature (client-side): No server secret
//     involved. Client chooses its own random blinding factor, so timing
//     leaks are self-inflicted and unexploitable.
//
//   - VerifySignature (public): All inputs are public data. Variable-time
//     big.Int.Cmp is acceptable.
//
// For future hardening, consider filippo.io/bigmod for constant-time RSA,
// but the existing blinding provides adequate protection.
package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

// mgf1SHA256 implements MGF1 (RFC 8017 B.2.1) with SHA-256.
func mgf1SHA256(seed []byte, length int) []byte {
	var out []byte
	var counter [4]byte
	for i := 0; len(out) < length; i++ {
		counter[0] = byte(i >> 24)
		counter[1] = byte(i >> 16)
		counter[2] = byte(i >> 8)
		counter[3] = byte(i)
		h := sha256.New()
		h.Write(seed)
		h.Write(counter[:])
		out = append(out, h.Sum(nil)...)
	}
	return out[:length]
}

// fdh computes a full-domain hash of the message, expanding to the full
// modulus size via MGF1-SHA256 and reducing mod n. This prevents the message
// hash from being much smaller than the modulus (F-6 fix).
// Returns an error if the output is zero (F-8 fix: prevents trivial forgery).
func fdh(message []byte, n *big.Int) (*big.Int, error) {
	nLen := (n.BitLen() + 7) / 8
	expanded := mgf1SHA256(append(blindDomainSeparator, message...), nLen)
	m := new(big.Int).SetBytes(expanded)
	m.Mod(m, n)
	if m.Sign() == 0 {
		return nil, fmt.Errorf("FDH produced zero output (astronomically unlikely)")
	}
	return m, nil
}

// GenerateBlindSigningKey generates an RSA keypair for use in the Chaum blind
// signature protocol. Minimum key size is 3072 bits (NIST SP 800-57 recommendation
// for security beyond 2030; 2048-bit RSA provides only ~112 bits of security).
func GenerateBlindSigningKey(bits int) (*rsa.PrivateKey, error) {
	if bits < 3072 {
		return nil, fmt.Errorf("RSA key size must be >= 3072 bits, got %d", bits)
	}
	return rsa.GenerateKey(rand.Reader, bits)
}

// blindDomainSeparator is prepended to the message before hashing in BlindMessage
// and VerifySignature to provide domain separation from other hash uses.
var blindDomainSeparator = []byte("bmail-blind-signature-v1:")

// BlindMessage blinds a message for the Chaum blind signature protocol.
// It hashes the message with a full-domain hash (FDH) using MGF1-SHA256
// expansion to the modulus size, picks a random blinding factor r coprime
// to n, and returns B = m * r^e mod n along with r.
func BlindMessage(message []byte, pubKey *rsa.PublicKey) (blinded *big.Int, blindingFactor *big.Int, err error) {
	// Full-domain hash of the message (F-6 fix).
	m, err := fdh(message, pubKey.N)
	if err != nil {
		return nil, nil, err
	}

	n := pubKey.N
	e := big.NewInt(int64(pubKey.E))

	// Pick random r coprime to n.
	for {
		r, err := rand.Int(rand.Reader, n)
		if err != nil {
			return nil, nil, err
		}
		// r must be > 0 and coprime to n.
		if r.Sign() == 0 {
			continue
		}
		gcd := new(big.Int).GCD(nil, nil, r, n)
		if gcd.Cmp(big.NewInt(1)) != 0 {
			continue
		}

		// B = m * r^e mod n
		re := new(big.Int).Exp(r, e, n)
		B := new(big.Int).Mul(m, re)
		B.Mod(B, n)

		return B, r, nil
	}
}

// SignBlinded signs a blinded message: S(B) = B^d mod n.
// Uses CRT (Chinese Remainder Theorem) when precomputed values are available,
// which is both faster and more resistant to fault-injection attacks.
// Returns an error if CRT fault verification fails (Shamir countermeasure, F-7 fix).
//
// Timing side-channel countermeasure (audit fix F-4): the input is re-blinded
// with a random factor before CRT exponentiation, so the secret exponents dP/dQ
// operate on randomized values. This prevents timing attacks on big.Int.Exp
// from leaking information about the private key.
func SignBlinded(blinded *big.Int, privKey *rsa.PrivateKey) (*big.Int, error) {
	// Ensure CRT precomputed values are available.
	privKey.Precompute()

	n := privKey.N
	e := big.NewInt(int64(privKey.E))
	p := privKey.Primes[0]
	q := privKey.Primes[1]
	dP := privKey.Precomputed.Dp
	dQ := privKey.Precomputed.Dq
	qInv := privKey.Precomputed.Qinv

	// Timing blinding: choose random r, compute B' = B * r^e mod n.
	// After signing, divide out r: S(B) = S(B') * r^(-1) mod n.
	// This randomizes the CRT inputs so timing of Exp reveals nothing
	// about dP/dQ.
	r, err := rand.Int(rand.Reader, n)
	if err != nil {
		return nil, fmt.Errorf("generate timing blind: %w", err)
	}
	for r.Sign() == 0 {
		r, err = rand.Int(rand.Reader, n)
		if err != nil {
			return nil, fmt.Errorf("generate timing blind: %w", err)
		}
	}

	re := new(big.Int).Exp(r, e, n)
	blindedInput := new(big.Int).Mul(blinded, re)
	blindedInput.Mod(blindedInput, n)

	// CRT: compute m1 = B'^dP mod p, m2 = B'^dQ mod q
	m1 := new(big.Int).Exp(blindedInput, dP, p)
	m2 := new(big.Int).Exp(blindedInput, dQ, q)

	// h = qInv * (m1 - m2) mod p
	h := new(big.Int).Sub(m1, m2)
	h.Mul(h, qInv)
	h.Mod(h, p)

	// blindedResult = m2 + h * q (this is B'^d mod n)
	blindedResult := new(big.Int).Mul(h, q)
	blindedResult.Add(blindedResult, m2)

	// Remove timing blind: result = blindedResult * r^(-1) mod n
	rInv := new(big.Int).ModInverse(r, n)
	if rInv == nil {
		return nil, fmt.Errorf("timing blind has no inverse (should not happen)")
	}
	result := new(big.Int).Mul(blindedResult, rInv)
	result.Mod(result, n)

	// Fault verification (Shamir countermeasure): verify result^e mod n == blinded
	check := new(big.Int).Exp(result, e, n)
	if check.Cmp(blinded) != 0 {
		return nil, fmt.Errorf("CRT fault detected: signature verification failed")
	}

	return result, nil
}

// UnblindSignature removes the blinding factor from the blind signature:
// S(m) = S(B) * r^(-1) mod n.
// Returns an error if the blinding factor has no modular inverse (i.e., it is
// not coprime to n), which would indicate a bug in the caller.
func UnblindSignature(blindSig *big.Int, blindingFactor *big.Int, pubKey *rsa.PublicKey) (*big.Int, error) {
	n := pubKey.N
	rInv := new(big.Int).ModInverse(blindingFactor, n)
	if rInv == nil {
		return nil, fmt.Errorf("blinding factor has no modular inverse (not coprime to n)")
	}
	s := new(big.Int).Mul(blindSig, rInv)
	s.Mod(s, n)
	return s, nil
}

// VerifySignature verifies a Chaum blind signature on a message:
// Check S(m)^e mod n == FDH(message) mod n.
func VerifySignature(message []byte, signature *big.Int, pubKey *rsa.PublicKey) bool {
	if signature == nil || signature.Sign() <= 0 {
		return false
	}

	n := pubKey.N
	e := big.NewInt(int64(pubKey.E))

	// s^e mod n
	lhs := new(big.Int).Exp(signature, e, n)

	// FDH(domain_separator || message) mod n (F-6 fix)
	rhs, err := fdh(message, n)
	if err != nil {
		return false // zero FDH is invalid
	}

	// big.Int.Cmp is not constant-time, but this is acceptable here:
	// both operands are derived from public data (signature, message, pubkey),
	// so there is no secret to leak via timing.
	return lhs.Cmp(rhs) == 0
}

// ErrInvalidSignature is returned when a blind signature verification fails.
var ErrInvalidSignature = errors.New("invalid blind signature")
