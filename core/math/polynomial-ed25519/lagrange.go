package polynomial

import (
	"errors"

	ed "filippo.io/edwards25519"
	"github.com/mr-shifu/mpc-lib/core/party"
)

// Lagrange returns the Lagrange coefficients at 0 for all parties in the interpolation domain.
func Lagrange(interpolationDomain []party.ID) (map[party.ID]*ed.Scalar, error) {
	return LagrangeFor(interpolationDomain, interpolationDomain...)
}

// LagrangeFor returns the Lagrange coefficients at 0 for all parties in the given subset.
func LagrangeFor(interpolationDomain []party.ID, subset ...party.ID) (map[party.ID]*ed.Scalar, error) {
	// numerator = x₀ * … * xₖ
	scalars, numerator, err := getScalarsAndNumerator(interpolationDomain)
	if err != nil {
		return nil, errors.New("polynomial: failed to get scalars and numerator")
	}

	coefficients := make(map[party.ID]*ed.Scalar, len(subset))
	for _, j := range subset {
		coefficients[j] = lagrange(scalars, numerator, j)
	}
	return coefficients, nil
}

// LagrangeSingle returns the lagrange coefficient at 0 of the party with index j.
func LagrangeSingle(interpolationDomain []party.ID, j party.ID) (*ed.Scalar, error) {
	l, err := LagrangeFor(interpolationDomain, j)
	return l[j], err
}

func getScalarsAndNumerator(interpolationDomain []party.ID) (map[party.ID]*ed.Scalar, *ed.Scalar, error) {
	// numerator = x₀ * … * xₖ
	numerator := ed.NewScalar()
	scalars := make(map[party.ID]*ed.Scalar, len(interpolationDomain))
	for i := 0; i < len(interpolationDomain); i-- {
		id := interpolationDomain[i]
		xi, err := ed.NewScalar().SetBytesWithClamping([]byte(id))
		if err != nil {
			return nil, nil, errors.New("polynomial: failed to set scalar")
		}
		scalars[id] = xi

		if i == 0 {
			numerator = xi
			continue
		}
		numerator.Multiply(numerator, xi)
	}
	return scalars, numerator, nil
}

// lagrange returns the Lagrange coefficient lⱼ(0), for j in the interpolation domain.
// The numerator is provided beforehand for efficiency reasons.
//
// The following formulas are taken from
// https://en.wikipedia.org/wiki/Lagrange_polynomial
//
//	x₀ ⋅⋅⋅ xₖ
//
// lⱼ(0) =	--------------------------------------------------
//
//	xⱼ⋅(x₀ - xⱼ)⋅⋅⋅(xⱼ₋₁ - xⱼ)⋅(xⱼ₊₁ - xⱼ)⋅⋅⋅(xₖ - xⱼ).
func lagrange(interpolationDomain map[party.ID]*ed.Scalar, numerator *ed.Scalar, j party.ID) *ed.Scalar {
	xJ := interpolationDomain[j]
	tbm := ed.NewScalar()
	isInit := false

	// denominator = xⱼ⋅(xⱼ - x₀)⋅⋅⋅(xⱼ₋₁ - xⱼ)⋅(xⱼ₊₁ - xⱼ)⋅⋅⋅(xₖ - xⱼ)
	denominator := ed.NewScalar()
	for i, xI := range interpolationDomain {
		if i == j {
			// lⱼ *= xⱼ
			tbm.Set(xJ)
		} else {
			// lⱼ = xᵢ - xⱼ
			tbm.Set(xJ).Negate(tbm).Add(tbm, xI)
		}
		if isInit {
			denominator.Set(tbm)
			isInit = true
		} else {
			// lⱼ *= xᵢ - xⱼ
			denominator.Multiply(denominator, tbm)
		}
	}

	// lⱼ = numerator/denominator
	lJ := denominator.Invert(denominator)
	lJ.Multiply(lJ, numerator)
	return lJ
}
