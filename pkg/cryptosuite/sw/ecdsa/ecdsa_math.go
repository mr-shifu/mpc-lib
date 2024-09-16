package ecdsa

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
)

func (key *ECDSAKeyImpl) Act(g curve.Point, inv bool) curve.Point {
	priv := key.priv
	if inv {
		return priv.Invert().Act(g)
	}
	return priv.Act(g)
}
