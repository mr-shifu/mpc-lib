package vssed25519

import (
	"testing"

	"github.com/mr-shifu/mpc-lib/core/math/polynomial-ed25519"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
	"github.com/stretchr/testify/assert"
)

func TestVssEd25519_NewVss(t *testing.T) {
	degree := 5

	constant, err := sample.Ed25519Scalar(nil)
	assert.NoError(t, err)

	poly, err := polynomial.GeneratePolynomial(degree, constant)
	assert.NoError(t, err)

	vss1 := NewVssKey(poly)
	assert.NotNil(t, vss1)

	// Test Case 1: Bytes
	bytes, err := vss1.Bytes()
	assert.NoError(t, err)
	assert.NotNil(t, bytes)

	// Test Case 2: FromBytes
	vss2 := new(VssKeyImpl)
	err = vss2.FromBytes(bytes)
	assert.NoError(t, err)
	assert.NotNil(t, vss2)
	assert.Equal(t, vss1.SKI(), vss2.SKI())

	// Test Case 3: SKI
	ski1 := vss1.SKI()
	ski2 := vss2.SKI()
	assert.NotNil(t, ski1)
	assert.NotNil(t, ski2)
	assert.Equal(t, ski1, ski2)

	// Test Case 4: Exponents
	vss3, err := vss1.Exponents()
	assert.NoError(t, err)
	assert.NotNil(t, vss3)
	assert.Equal(t, vss1.SKI(), vss3.SKI())

	// Test Case 5: Private
	assert.True(t, vss1.Private())
	assert.True(t, vss2.Private())
	assert.False(t, vss3.Private())

	// Test Case 6: ExponentsRaw
	p, err := vss1.ExponentsRaw()
	assert.NoError(t, err)
	assert.NotNil(t, p)
	assert.Equal(t, poly.Exponents(), p.Exponents())

	// Test Case 7: Evaluate
	x, err := sample.Ed25519Scalar(nil)
	assert.NoError(t, err)

    v, err := poly.Evaluate(x)
	assert.NoError(t, err)

	v1, err := vss1.Evaluate(x)
	assert.NoError(t, err)
	assert.NotNil(t, v1)
	
	v2, err := vss2.Evaluate(x)
	assert.NoError(t, err)
	assert.NotNil(t, v2)
	assert.Equal(t, 1, v.Equal(v2))

	// Test Case 8: EvaluateExponents
	V, err := poly.EvaluateExponent(x)
	assert.NoError(t, err)

	V1, err := vss1.EvaluateByExponents(x)
	assert.NoError(t, err)

	V2, err := vss2.EvaluateByExponents(x)
	assert.NoError(t, err)

	V3, err := vss1.EvaluateByExponents(x)
	assert.NoError(t, err)
	assert.NotNil(t, V3)
	assert.Equal(t, 1, V1.Equal(V))
	assert.Equal(t, 1, V2.Equal(V))
	assert.Equal(t, 1, V3.Equal(V))
}
