//go:build js && wasm

package main

import (
	"fmt"
	"syscall/js"
)

// ── Password validation ─────────────────────────────────────

// validatePasswordStrength checks password strength requirements.
// Mirrors internal/security.ValidatePassword but runs client-side
// in WASM since OPAQUE prevents the server from seeing the raw password.
func validatePasswordStrength(pwd string) error {
	if len(pwd) < 12 {
		return fmt.Errorf("password must be at least 12 characters")
	}
	classes := 0
	hasLower, hasUpper, hasDigit, hasSpecial := false, false, false, false
	for _, r := range pwd {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}
	if hasLower {
		classes++
	}
	if hasUpper {
		classes++
	}
	if hasDigit {
		classes++
	}
	if hasSpecial {
		classes++
	}
	if classes < 2 {
		return fmt.Errorf("password is too weak: requires at least 2 character classes (lowercase, uppercase, digits, special)")
	}
	return nil
}

// validatePasswordJS exposes password validation to JavaScript so the frontend
// can check before initiating OPAQUE registration.
func validatePasswordJS(args []js.Value) (interface{}, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("validatePassword requires 1 arg: password")
	}
	pwd := args[0].String()
	if err := validatePasswordStrength(pwd); err != nil {
		return err.Error(), nil
	}
	return nil, nil
}
