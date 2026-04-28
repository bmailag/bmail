package crypto

import "runtime"

// ZeroBytes overwrites every byte in b with zero.
// Used to clear sensitive key material from memory after use.
// Uses Go's clear() builtin (Go 1.21+), which is a language-level construct
// that the compiler must honor — it cannot be optimized away.
//
// runtime.KeepAlive prevents the GC from collecting the backing array before
// zeroing completes (audit fix F-A6).
//
// SECURITY NOTE (F-9): Go's garbage collector may copy heap-allocated slices
// before ZeroBytes is called, leaving stale copies in freed memory. This is
// an inherent limitation of Go's managed runtime — there is no mlock/madvise
// equivalent in Go. Mitigations:
//   - Call ZeroBytes via defer immediately after key derivation to minimize window.
//   - Prefer fixed-size arrays ([32]byte) on the stack where possible.
//   - For production SGX deployments, enclave memory is encrypted by hardware,
//     making GC copies less exploitable.
func ZeroBytes(b []byte) {
	clear(b)
	runtime.KeepAlive(b)
}

// ZeroArray32 zeroes a 32-byte array in place.
// Prefer this for stack-allocated [32]byte secrets to avoid heap escapes
// that ZeroBytes(slice[:]) would cause (audit fix F-A6).
func ZeroArray32(a *[32]byte) {
	*a = [32]byte{}
	runtime.KeepAlive(a)
}
