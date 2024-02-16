package vss

import "github.com/mr-shifu/mpc-lib/core/math/curve"

type VssKey interface {
	// Bytes returns the byte representation of the vss coefficients.
	Bytes() ([]byte, error)

	// SKI returns the serialized key identifier.
	SKI() []byte

	// Private returns true if the key is private.
	Private() bool

	// PublicKey returns the corresponding Exponents of coefficients.
	Exponents() (VssKey, error)

	// Evaluate evaluates polynomial at a scalar using coefficients.
	Evaluate(index curve.Scalar) (curve.Scalar, error)

	// EvaluateByExponents evaluates polynomial using exponents of coefficients.
	EvaluateByExponents(index curve.Scalar) (curve.Point, error)
}

type VssKeyManager interface {
	// GenerateSecrets generates a Polynomail of a specified degree with secret as constant value
	// and stores coefficients and expponents of coefficients.
	GenerateSecrets(secret curve.Scalar, degree int) (VssKey, error)

	// ImportSecrets imports exponents of coefficients and returns VssKey.
	ImportSecrets(exponents []curve.Point) (VssKey, error)

	// GetSecrets returns VssKey of coefficients.
	GetSecrets(ski []byte) (VssKey, error)

	// Evaluate evaluates polynomial at a scalar using coefficients.
	Evaluate(ski []byte, index curve.Scalar) (curve.Scalar, error)

	// EvaluateByExponents evaluates polynomial using exponents of coefficients.
	EvaluateByExponents(ski []byte, index curve.Scalar) (curve.Point, error)
}
