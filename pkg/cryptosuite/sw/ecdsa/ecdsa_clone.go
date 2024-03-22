package ecdsa

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	comm_ecdsa "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/ecdsa"
)

func (key ECDSAKey) CloneByMultiplier(c curve.Scalar) comm_ecdsa.ECDSAKey {
	group := key.group
	cloned := ECDSAKey{
		group: group,
	}
	if key.Private() {
		cloned.priv = group.NewScalar().Set(c).Mul(key.priv)
	}
	cloned.pub = c.Act(key.pub)
	return cloned
}

func (key ECDSAKey) CloneByKeyMultiplier(multiplierKey comm_ecdsa.ECDSAKey, c curve.Scalar) comm_ecdsa.ECDSAKey {
	group := key.group
	mk, ok := multiplierKey.(ECDSAKey)
	if !ok {
		return nil
	}
	cloned := ECDSAKey{
		group: group,
	}
	if key.Private() {
		cloned.priv = group.NewScalar().Set(key.priv).Mul(mk.priv).Add(c)
	}
	cloned.pub = c.Act(key.pub)
	
	return cloned
}