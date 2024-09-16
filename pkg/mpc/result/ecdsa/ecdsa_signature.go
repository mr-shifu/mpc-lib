package ecdsa

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/result"
)

type EcdsaSignature struct {
	r     curve.Point
	sigma curve.Scalar
}

var _ result.EcdsaSignature = (*EcdsaSignature)(nil)

func NewEcdsaSignature(r curve.Point, sigma curve.Scalar) *EcdsaSignature {
	return &EcdsaSignature{r: r, sigma: sigma}
}

func (es *EcdsaSignature) SetR(r curve.Point) {
	es.r = r
}

func (es *EcdsaSignature) SetSigma(sigma curve.Scalar) {
	es.sigma = sigma
}

func (es *EcdsaSignature) SignR() curve.Point {
	return es.r
}

func (es *EcdsaSignature) SignSigma() curve.Scalar {
	return es.sigma
}
