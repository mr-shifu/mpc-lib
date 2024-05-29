package polynomial

import (
	"testing"

	ed "filippo.io/edwards25519"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
	"github.com/stretchr/testify/assert"
)

func TestPolynomial_NewPolynomial(t *testing.T) {
	constant, err := sample.Ed25519Scalar()
	constant_exp := (&ed.Point{}).ScalarBaseMult(constant)
	assert.NoError(t, err)

	degree := 2
	poly, err := NewPolynomial(degree, constant)
	assert.NotNil(t, poly)
	assert.NoError(t, err)
	assert.Equal(t, degree+1, len(poly.coefficients))
	assert.Equal(t, degree+1, len(poly.exponents))
	assert.Equal(t, constant, poly.coefficients[0])

	assert.True(t, poly.Private())
	assert.Equal(t, 1, constant_exp.Equal(poly.Constant()))
}
