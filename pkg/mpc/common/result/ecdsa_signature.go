package result

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
)

type EcdsaSignature interface {
	SetR(r curve.Point)
	SetSigma(sigma curve.Scalar)
	SignR() curve.Point
	SignSigma() curve.Scalar
}

type EcdsaSignatureStore interface {
	Import(sig EcdsaSignature, opts keyopts.Options) error
	Get(opts keyopts.Options) (EcdsaSignature, error)
}

type EcdsaSignatureManager interface {
	NewEcdsaSignature(r curve.Point, sigma curve.Scalar) EcdsaSignature
	Import(sig EcdsaSignature, opts keyopts.Options) error
	SetR(r curve.Point, opts keyopts.Options) error
	SetSigma(sigma curve.Scalar, opts keyopts.Options) error
	Get(opts keyopts.Options) (EcdsaSignature, error)
}
