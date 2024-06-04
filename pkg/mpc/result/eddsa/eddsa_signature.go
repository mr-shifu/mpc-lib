package result

import (
	"filippo.io/edwards25519"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/result"
)

type EddsaSignature struct {
	r *edwards25519.Point
	z *edwards25519.Scalar
}

func NewEddsaSignature(r *edwards25519.Point, z *edwards25519.Scalar) result.EddsaSignature {
	return &EddsaSignature{r: r, z: z}
}

func (es *EddsaSignature) SetR(r *edwards25519.Point) {
	es.r = r
}

func (es *EddsaSignature) SetZ(z *edwards25519.Scalar) {
	es.z = z
}

func (es *EddsaSignature) R() *edwards25519.Point {
	return es.r
}

func (es *EddsaSignature) Z() *edwards25519.Scalar {
	return es.z
}
