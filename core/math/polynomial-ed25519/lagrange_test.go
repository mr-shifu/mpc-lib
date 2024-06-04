package polynomial

import (
	"testing"

	ed "filippo.io/edwards25519"
	"github.com/mr-shifu/mpc-lib/lib/test"
	"github.com/stretchr/testify/assert"
)

func scalarOne() *ed.Scalar {
	one := make([]byte, 32)
	one[0] = 1

	// Create the scalar
	scalarOne, _ := ed.NewScalar().SetCanonicalBytes(one)
	return scalarOne
}

func TestPolynomial_getScalarsAndNumerator(t *testing.T) {
	N := 10
	allIDs := test.PartyIDs(N)

	scalars, numerator, err := getScalarsAndNumerator(allIDs)
	assert.NoError(t, err)

	one := scalarOne()
	prod := ed.NewScalar().Set(one)
	for _, s := range scalars {
		prod.Multiply(prod, s)
	}

	assert.Equal(t, 1, prod.Equal(numerator))
}

func TestPolynomial_Lagrange(t *testing.T) {
	one := scalarOne()

	N := 10
	allIDs := test.PartyIDs(N)

	coefs, err := Lagrange(allIDs)
	assert.NoError(t, err)

	sum := ed.NewScalar()
	for _, c := range coefs {
		sum.Add(sum, c)
	}
	assert.Equal(t, 1, sum.Equal(one))
}
