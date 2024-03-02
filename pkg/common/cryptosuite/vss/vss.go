package vss

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/math/polynomial"
)

type VSSShare struct {
	Index  curve.Scalar
	Secret curve.Scalar
	Public curve.Point
}

type VSSShareStore interface {
	// GetShare returns a share (x, f(x)) for a given index.
	Get(ski []byte, index curve.Scalar) (*VSSShare, error)

	// ImportShare imports a share (x, f(x)) and stores it.
	Import(ski []byte, share *VSSShare) error

	WithSKI(ski []byte) (LinkedVSSShareStore, error)
}

type LinkedVSSShareStore interface {
	// GetShare returns a share (x, f(x)) for a given index.
	Get(index curve.Scalar) (*VSSShare, error)

	// ImportShare imports a share (x, f(x)) and stores it.
	Import(share *VSSShare) error
}

type VssKey interface {
	// Bytes returns the byte representation of the vss coefficients.
	Bytes() ([]byte, error)

	// SKI returns the serialized key identifier.
	SKI() []byte

	// Private returns true if the key is private.
	Private() bool

	// Exponents returns the corresponding Exponents of coefficients.
	Exponents() (VssKey, error)

	// ExponentsRaw returns the corresponding Raw Exponents of coefficients.
	ExponentsRaw() (*polynomial.Exponent, error)

	// Evaluate evaluates polynomial at a scalar using coefficients.
	Evaluate(index curve.Scalar) (curve.Scalar, error)

	// EvaluateByExponents evaluates polynomial using exponents of coefficients.
	EvaluateByExponents(index curve.Scalar) (curve.Point, error)

	// TODO much better to be removed
	WithShareStore(ss LinkedVSSShareStore)

	// ImportShare imports a share (x, f(x)) and stores it.
	ImportShare(share *VSSShare) error

	// GetShare returns a share (x, f(x)) for a given index.
	GetShare(index curve.Scalar) (*VSSShare, error)
}

type VssKeyManager interface {
	// GenerateSecrets generates a Polynomail of a specified degree with secret as constant value
	// and stores coefficients and expponents of coefficients.
	GenerateSecrets(secret curve.Scalar, degree int) (VssKey, error)

	// ImportSecrets imports exponents of coefficients and returns VssKey.
	ImportSecrets(exponents []byte) (VssKey, error)

	// GetSecrets returns VssKey of coefficients.
	GetSecrets(ski []byte) (VssKey, error)

	// Evaluate evaluates polynomial at a scalar using coefficients.
	Evaluate(ski []byte, index curve.Scalar) (curve.Scalar, error)

	// EvaluateByExponents evaluates polynomial using exponents of coefficients.
	EvaluateByExponents(ski []byte, index curve.Scalar) (curve.Point, error)
}
