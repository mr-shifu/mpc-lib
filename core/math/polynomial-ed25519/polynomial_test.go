package polynomial

import (
	"testing"

	ed "filippo.io/edwards25519"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
	"github.com/stretchr/testify/assert"
)

var (
	ScalarZero = ed.NewScalar()
	PointZero  = (&ed.Point{}).ScalarBaseMult(ScalarZero)
)

func TestPolynomial_GeneratePolynomial(t *testing.T) {
	constant, err := sample.Ed25519Scalar()
	constant_exp := (&ed.Point{}).ScalarBaseMult(constant)
	assert.NoError(t, err)

	// Test Case 1: Invalid constant
	_, err = GeneratePolynomial(2, nil)
	assert.Error(t, err)

	_, err = GeneratePolynomial(2, ScalarZero)
	assert.Error(t, err)

	// Test Case 2: Valid constant
	for degree := 0; degree < 10; degree++ {
		poly, err := GeneratePolynomial(degree, constant)
		assert.NotNil(t, poly)
		assert.NoError(t, err)
		assert.Equal(t, degree+1, len(poly.coefficients))
		assert.Equal(t, degree+1, len(poly.exponents))
		assert.Equal(t, constant, poly.coefficients[0])
		assert.Equal(t, constant_exp, poly.exponents[0])
		assert.Equal(t, constant_exp, poly.Constant())
		assert.Equal(t, degree, poly.Degree())
		assert.True(t, poly.Private())
	}
}
