package result

import "github.com/mr-shifu/mpc-lib/core/math/curve"

type SigmaStore interface {
	ImportSigma(signID, partyID string, sigma curve.Scalar) error
	GetSigma(signID, partyID string) (curve.Scalar, error)
}
