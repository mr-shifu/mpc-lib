package eddsa

import (
	"github.com/mr-shifu/mpc-lib/core/hash"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
)

type Signature struct {
	R curve.Point
	Z curve.Scalar
}

func Verify(public curve.Point, sig Signature, msg []byte) bool {
	group := public.Curve()

	challengeHash := hash.New()
	_ = challengeHash.WriteAny(sig.R, public, msg)
	challenge := sample.Scalar(challengeHash.Digest(), group)

	expected := challenge.Act(public)
	expected = expected.Add(sig.R)

	actual := sig.Z.ActOnBase()

	return expected.Equal(actual)
}
