package result

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/result"
)

type EddsaSignature struct {
	r curve.Point
	z curve.Scalar
}

func NewEddsaSignature(r curve.Point, z curve.Scalar) result.EddsaSignature {
	return &EddsaSignature{r: r, z: z}
}

func (es *EddsaSignature) SetR(r curve.Point) {
	es.r = r
}

func (es *EddsaSignature) SetZ(z curve.Scalar) {
	es.z = z
}

func (es *EddsaSignature) R() curve.Point {
	return es.r
}

func (es *EddsaSignature) Z() curve.Scalar {
	return es.z
}