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

func TestPolynomial_NewPolynomial(t *testing.T) {
	constant, err := sample.Ed25519Scalar()
	constant_exp := (&ed.Point{}).ScalarBaseMult(constant)
	assert.NoError(t, err)

	// Test Case 1: Invalid constant
	_, err = NewPolynomial(2, nil)
	assert.Error(t, err)

	_, err = NewPolynomial(2, ScalarZero)
	assert.Error(t, err)

	// Test Case 2: Valid constant
	degree := 2
	poly, err := NewPolynomial(degree, constant)
	assert.NotNil(t, poly)
	assert.NoError(t, err)
	assert.Equal(t, degree+1, len(poly.coefficients))
	assert.Equal(t, degree+1, len(poly.exponents))
	assert.Equal(t, constant, poly.coefficients[0])
	assert.Equal(t, 1, constant_exp.Equal(poly.Constant()))
	assert.True(t, poly.Private())
}


