package result

import "github.com/mr-shifu/mpc-lib/core/math/curve"

type Signature interface {
	ImportSignR(signID string, r curve.Point)
	SignR(signID string) curve.Point
	ImportSignSigma(signID string, sigma curve.Scalar)
	SignSigma(signID string) curve.Scalar
}
