package result

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
)

type SigmaStore interface {
	ImportSigma(sigma curve.Scalar, opts keyopts.Options) error
	GetSigma(opts keyopts.Options) (curve.Scalar, error)
}
