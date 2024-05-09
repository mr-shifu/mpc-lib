package result

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
)

type EddsaSignature interface {
	SetR(r curve.Point) 
	SetZ(z curve.Scalar)
	R() curve.Point
	Z() curve.Scalar
}

type EddsaSignatureStore interface {
	Import(sig EddsaSignature, opts keyopts.Options) error
	Get(opts keyopts.Options) (EddsaSignature, error)
}

type EddsaSignatureManager interface {
	NewEddsaSignature(r curve.Point, z curve.Scalar) EddsaSignature
	Import(sig EddsaSignature, opts keyopts.Options) error
	SetR(R curve.Point, opts keyopts.Options) error
	SetZ(z curve.Scalar, opts keyopts.Options) error
	Get(opts keyopts.Options) (EddsaSignature, error)
}

