package ecdsa

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	comm_ecdsa "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/ecdsa"
)

func (key ECDSAKey) Act(g curve.Point, inv bool) curve.Point {
	priv := key.priv
	if inv {
		return priv.Invert().Act(g)
	}
	return priv.Act(g)
}

func (key ECDSAKey) Commit(m curve.Scalar, c curve.Scalar) curve.Scalar {
	return key.group.NewScalar().Set(key.priv).Mul(m).Add(c)
}

func (key ECDSAKey) CommitByKey(multiplierKey comm_ecdsa.ECDSAKey, c curve.Scalar) curve.Scalar {
	group := key.group
	mk, ok := multiplierKey.(ECDSAKey)
	if !ok {
		return nil
	}
	return group.NewScalar().Set(key.priv).Mul(mk.priv).Add(c)
}

func (key ECDSAKey) Mul(c curve.Scalar) curve.Scalar {
	return key.group.NewScalar().Set(c).Mul(key.priv)
}

func (key ECDSAKey) AddKeys(keys ...comm_ecdsa.ECDSAKey) curve.Scalar {
	group := key.group
	sum := group.NewScalar().Set(key.priv)
	for _, k := range keys {
		k, ok := k.(ECDSAKey)
		if !ok {
			return nil
		}
		sum = sum.Add(group.NewScalar().Set(k.priv))
	}
	return sum
}
