package crypto

import (
	"crypto/mlkem"
	"fmt"
)

const (
	MLKEMEncapsulationKeySize = 1184
	MLKEMDecapsulationKeySize = 64 // seed form
	MLKEMCiphertextSize       = 1088
	MLKEMSharedSecretSize     = 32
)

type MLKEMKeyPair struct {
	EncapsulationKey *mlkem.EncapsulationKey768
	DecapsulationKey *mlkem.DecapsulationKey768
}

func GenerateMLKEMKeyPair() (*MLKEMKeyPair, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("generate ML-KEM-768 key: %w", err)
	}
	return &MLKEMKeyPair{
		EncapsulationKey: dk.EncapsulationKey(),
		DecapsulationKey: dk,
	}, nil
}

func MLKEMEncapsulationKeyFromBytes(b []byte) (*mlkem.EncapsulationKey768, error) {
	if len(b) != MLKEMEncapsulationKeySize {
		return nil, fmt.Errorf("ML-KEM encapsulation key must be %d bytes, got %d", MLKEMEncapsulationKeySize, len(b))
	}
	ek, err := mlkem.NewEncapsulationKey768(b)
	if err != nil {
		return nil, fmt.Errorf("parse ML-KEM encapsulation key: %w", err)
	}
	return ek, nil
}

func MLKEMDecapsulationKeyFromBytes(seed []byte) (*mlkem.DecapsulationKey768, error) {
	if len(seed) != MLKEMDecapsulationKeySize {
		return nil, fmt.Errorf("ML-KEM decapsulation key seed must be %d bytes, got %d", MLKEMDecapsulationKeySize, len(seed))
	}
	dk, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return nil, fmt.Errorf("parse ML-KEM decapsulation key: %w", err)
	}
	return dk, nil
}
