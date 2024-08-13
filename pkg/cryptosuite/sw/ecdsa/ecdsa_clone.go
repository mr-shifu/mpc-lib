package ecdsa

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
)

func (key *ECDSAKeyImpl) CloneByMultiplier(c curve.Scalar) ECDSAKey {
	group := key.group
	cloned := ECDSAKeyImpl{
		group: group,
	}
	if key.Private() {
		cloned.priv = group.NewScalar().Set(c).Mul(key.priv)
	}
	cloned.pub = c.Act(key.pub)
	return &cloned
}

func (key *ECDSAKeyImpl) CloneByKeyMultiplier(multiplierKey ECDSAKey, c curve.Scalar) ECDSAKey {
	group := key.group
	mk, ok := multiplierKey.(*ECDSAKeyImpl)
	if !ok {
		return nil
	}
	cloned := ECDSAKeyImpl{
		group: group,
	}
	if key.Private() {
		cloned.priv = group.NewScalar().Set(key.priv).Mul(mk.priv).Add(c)
	}
	cloned.pub = c.Act(key.pub)
	
	return &cloned
}