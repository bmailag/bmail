//go:build js && wasm

package main

import (
	"crypto/mlkem"
	"encoding/base64"
	"fmt"
	"syscall/js"

	"github.com/bmailag/bmail/internal/crypto"
)

// jsFunc wraps a Go function that returns (interface{}, error) into a js.Func.
func jsFunc(fn func(args []js.Value) (interface{}, error)) js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		// Return a Promise to the JS caller.
		handler := js.FuncOf(func(_ js.Value, promiseArgs []js.Value) interface{} {
			resolve := promiseArgs[0]
			reject := promiseArgs[1]

			go func() {
				result, err := fn(args)
				if err != nil {
					reject.Invoke(js.Global().Get("Error").New(err.Error()))
					return
				}
				resolve.Invoke(result)
			}()

			return nil
		})
		return js.Global().Get("Promise").New(handler)
	})
}

// b64 encodes bytes to base64.
func b64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// unb64 decodes base64 to bytes.
func unb64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// toJSObject converts a map to a JS object.
func toJSObject(m map[string]interface{}) js.Value {
	obj := js.Global().Get("Object").New()
	for k, v := range m {
		obj.Set(k, v)
	}
	return obj
}

// ── Hybrid KEM helpers ──────────────────────────────────────

// parseOptionalKEMEK extracts and parses an optional ML-KEM-768 encapsulation
// key from the given argument position. Returns nil if the arg is absent,
// undefined, null, or empty string.
func parseOptionalKEMEK(args []js.Value, idx int) (*mlkem.EncapsulationKey768, error) {
	if idx >= len(args) {
		return nil, nil
	}
	v := args[idx]
	if v.IsUndefined() || v.IsNull() || v.String() == "" {
		return nil, nil
	}
	ekBytes, err := unb64(v.String())
	if err != nil {
		return nil, fmt.Errorf("decode KEM encapsulation key: %w", err)
	}
	ek, err := crypto.MLKEMEncapsulationKeyFromBytes(ekBytes)
	if err != nil {
		return nil, err
	}
	return ek, nil
}

// parseOptionalKEMDK extracts and parses an optional ML-KEM-768 decapsulation
// key (seed form) from the given argument position. Returns nil if the arg is
// absent, undefined, null, or empty string.
func parseOptionalKEMDK(args []js.Value, idx int) (*mlkem.DecapsulationKey768, error) {
	if idx >= len(args) {
		return nil, nil
	}
	v := args[idx]
	if v.IsUndefined() || v.IsNull() || v.String() == "" {
		return nil, nil
	}
	dkBytes, err := unb64(v.String())
	if err != nil {
		return nil, fmt.Errorf("decode KEM decapsulation key: %w", err)
	}
	dk, err := crypto.MLKEMDecapsulationKeyFromBytes(dkBytes)
	if err != nil {
		return nil, err
	}
	return dk, nil
}
