package vssed25519

import (
	ed "filippo.io/edwards25519"
	"github.com/mr-shifu/mpc-lib/core/math/polynomial-ed25519"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
)

type VssKey interface {
	// Bytes returns the byte representation of the vss coefficients.
	Bytes() ([]byte, error)

	FromBytes(data []byte) error

	// SKI returns the serialized key identifier.
	SKI() []byte

	// Private returns true if the key is private.
	Private() bool

	// Exponents returns the corresponding Exponents of coefficients.
	Exponents() (VssKey, error)

	// ExponentsRaw returns the corresponding Raw Exponents of coefficients.
	ExponentsRaw() (*polynomial.Polynomial, error)

	// Evaluate evaluates polynomial at a scalar using coefficients.
	Evaluate(index *ed.Scalar) (*ed.Scalar, error)

	// EvaluateByExponents evaluates polynomial using exponents of coefficients.
	EvaluateByExponents(index *ed.Scalar) (*ed.Point, error)
}

type VssKeyManager interface {
	// GenerateSecrets generates a Polynomail of a specified degree with secret as constant value
	// and stores coefficients and expponents of coefficients.
	GenerateSecrets(secret *ed.Scalar, degree int, opts keyopts.Options) (VssKey, error)

	// ImportSecrets imports exponents of coefficients and returns VssKey.
	ImportSecrets(key any, opts keyopts.Options) (VssKey, error)

	// GetSecrets returns VssKey of coefficients.
	GetSecrets(opts keyopts.Options) (VssKey, error)

	// Evaluate evaluates polynomial at a scalar using coefficients.
	Evaluate(index *ed.Scalar, opts keyopts.Options) (*ed.Scalar, error)

	// EvaluateByExponents evaluates polynomial using exponents of coefficients.
	EvaluateByExponents(index *ed.Scalar, opts keyopts.Options) (*ed.Point, error)

	SumExponents(optsList ...keyopts.Options) (VssKey, error)
}
