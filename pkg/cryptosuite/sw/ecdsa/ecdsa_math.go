package ecdsa

import (
	"github.com/cronokirby/saferith"
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
	g := key.group
	cmt := new(saferith.Int).Mul(curve.MakeInt(key.priv), curve.MakeInt(m), -1)
	cmt = cmt.Add(cmt, curve.MakeInt(c), -1)
	return g.NewScalar().SetNat(cmt.Mod(g.Order()))
}

func (key ECDSAKey) CommitByKey(multiplierKey comm_ecdsa.ECDSAKey, c curve.Scalar) curve.Scalar {
	group := key.group
	mk, ok := multiplierKey.(ECDSAKey)
	if !ok {
		return nil
	}
	cmt := new(saferith.Int).Mul(curve.MakeInt(key.priv), curve.MakeInt(mk.priv), -1)
	cmt = cmt.Add(cmt, curve.MakeInt(c), -1)
	return group.NewScalar().SetNat(cmt.Mod(group.Order()))
}

func (key ECDSAKey) Mul(c curve.Scalar) curve.Scalar {
	return key.group.NewScalar().Set(c).Mul(key.priv)
}

func (key ECDSAKey) AddKeys(keys ...comm_ecdsa.ECDSAKey) curve.Scalar {
	group := key.group
	sum := group.NewScalar().SetNat(curve.MakeInt(key.priv).Mod(group.Order())) // group.NewScalar().Set(key.priv)
	for _, k := range keys {
		k, ok := k.(ECDSAKey)
		if !ok {
			return nil
		}
		sum = sum.Add(group.NewScalar().SetNat(curve.MakeInt(k.priv).Mod(group.Order())))
	}
	return group.NewScalar().SetNat(curve.MakeInt(sum).Mod(group.Order()))
}
