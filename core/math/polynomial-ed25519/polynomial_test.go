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
		assert.NoError(t, err)
		assert.NotNil(t, poly)
		assert.Equal(t, degree+1, len(poly.coefficients))
		assert.Equal(t, degree+1, len(poly.exponents))
		assert.Equal(t, constant, poly.coefficients[0])
		assert.Equal(t, constant_exp, poly.exponents[0])
		assert.Equal(t, constant_exp, poly.Constant())
		assert.Equal(t, degree, poly.Degree())
		assert.True(t, poly.Private())
	}
}

func TestPolynomial_NewPolynomial(t *testing.T) {
	constant, err := sample.Ed25519Scalar()
	constant_exp := (&ed.Point{}).ScalarBaseMult(constant)
	assert.NoError(t, err)

	degree := 5
	poly1, err := GeneratePolynomial(degree, constant)
	assert.NoError(t, err)

	poly2, err := GeneratePolynomial(degree, constant)
	assert.NoError(t, err)

	// Test Case 1: Exponents nil should throw error
	_, err = NewPolynomial(degree, poly1.coefficients, nil)
	assert.Error(t, err)

	// Test Case 2: Degree does not match with exponents
	_, err = NewPolynomial(degree+1, nil, poly1.exponents)
	assert.Error(t, err)

	// Test Case 3: coeffiecients are not matcher with exponents
	_, err = NewPolynomial(degree, poly1.coefficients, poly2.exponents)
	assert.Error(t, err)

	// Test Case 4: NewPolynomial with only exponents
	poly, err := NewPolynomial(degree, nil, poly1.exponents)
	assert.NoError(t, err)
	assert.NotNil(t, poly)
	assert.Nil(t, poly.coefficients)
	assert.Equal(t, degree+1, len(poly.exponents))
	assert.Equal(t, constant_exp, poly.exponents[0])
	assert.Equal(t, constant_exp, poly.Constant())
	assert.Equal(t, degree, poly.Degree())
	assert.False(t, poly.Private())

	// Test Case 5: NewPolynomial with coeffiecients and exponents
	poly, err = NewPolynomial(degree, poly1.coefficients, poly1.exponents)
	assert.NoError(t, err)
	assert.NotNil(t, poly)
	assert.Equal(t, degree+1, len(poly.coefficients))
	assert.Equal(t, degree+1, len(poly.exponents))
	assert.Equal(t, constant, poly.coefficients[0])
	assert.Equal(t, constant_exp, poly.exponents[0])
	assert.Equal(t, constant_exp, poly.Constant())
	assert.Equal(t, degree, poly.Degree())
	assert.True(t, poly.Private())
}

func TestPolynomial_Evaluate(t *testing.T) {
	constant, err := sample.Ed25519Scalar()
	assert.NoError(t, err)

	degree := 1
	poly, err := GeneratePolynomial(degree, constant)
	assert.NoError(t, err)

	// Test Case 1: Evaluate polynomial at 0
	_, err = poly.Evaluate(ScalarZero)
	assert.Error(t, err)

	_, err = poly.Evaluate(nil)
	assert.Error(t, err)

	// Test Case 2: Evaluate polynomial at random scalar
	x, err := sample.Ed25519Scalar()
	assert.NoError(t, err)

	y, err := poly.Evaluate(x)
	assert.NoError(t, err)

	Y, err := poly.EvaluateExponent(x)
	assert.NoError(t, err)

	yG := new(ed.Point).ScalarBaseMult(y)
	assert.Equal(t, 1, Y.Equal(yG))
}
