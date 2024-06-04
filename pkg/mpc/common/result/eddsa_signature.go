package result

import (
	ed "filippo.io/edwards25519"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
)

type EddsaSignature interface {
	SetR(r *ed.Point)
	SetZ(z *ed.Scalar)
	R() *ed.Point
	Z() *ed.Scalar
}

type EddsaSignatureStore interface {
	Import(sig EddsaSignature, opts keyopts.Options) error
	Get(opts keyopts.Options) (EddsaSignature, error)
}

type EddsaSignatureManager interface {
	NewEddsaSignature(r *ed.Point, z *ed.Scalar) EddsaSignature
	Import(sig EddsaSignature, opts keyopts.Options) error
	SetR(R *ed.Point, opts keyopts.Options) error
	SetZ(z *ed.Scalar, opts keyopts.Options) error
	Get(opts keyopts.Options) (EddsaSignature, error)
}
