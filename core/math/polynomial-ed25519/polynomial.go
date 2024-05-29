package polynomial

import (
	ed "filippo.io/edwards25519"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
	"github.com/pkg/errors"
)

const (
	CoefficientSize = 32
	ExponentSize    = 32
)

type Polynomial struct {
	coefficients []*ed.Scalar
	exponents    []*ed.Point
}

// NewPolynomial generates a Polynomial:
// f(X) = secret + a₁⋅X + … + aₜ⋅Xᵗ,
// F(X) = A₀ + A₁⋅X + … + Aₜ⋅Xᵗ,
// where Aᵢ = aᵢ•G, and G is the base point of the curve.
// with coefficients in ℤₚ, and degree t.
func GeneratePolynomial(degree int, constant *ed.Scalar) (*Polynomial, error) {
	// throw erro if the constant is nil or Zero.
	if constant == nil || constant.Equal(ed.NewScalar()) == 1 {
		return nil, errors.New("polynomial: invalid constant")
	}

	polynomial := &Polynomial{
		coefficients: make([]*ed.Scalar, degree+1),
		exponents:    make([]*ed.Point, degree+1),
	}

	polynomial.coefficients[0] = constant
	polynomial.exponents[0] = (&ed.Point{}).ScalarBaseMult(constant)

	for i := 1; i <= degree; i++ {
		c, err := sample.Ed25519Scalar()
		if err != nil {
			return nil, errors.WithMessage(err, "polynomial: failed to sample scalar")
		}
		polynomial.coefficients[i] = c
		polynomial.exponents[i] = (&ed.Point{}).ScalarBaseMult(c)
	}

	return polynomial, nil
}

func NewPolynomial(degree int, coefficients []*ed.Scalar, exponents []*ed.Point) (*Polynomial, error) {
	if exponents == nil {
		return nil, errors.New("polynomial: exponents cannot be nil")
	}
	if coefficients == nil {
		if len(exponents) != degree+1 {
			return nil, errors.New("polynomial: degree does not match with exponents")
		}
		return &Polynomial{
			coefficients: nil,
			exponents:    exponents,
		}, nil
	} else {
		if len(coefficients) != degree+1 {
			return nil, errors.New("polynomial: degree does not match with coefficients")
		}
		if len(coefficients) != len(exponents) {
			return nil, errors.New("polynomial: coefficients and exponents length mismatch")
		}
		for i := 0; i <= degree; i++ {
			if exponents[i].Equal((&ed.Point{}).ScalarBaseMult(coefficients[i])) != 1 {
				return nil, errors.New("polynomial: exponent doesn't match coefficient")
			}
		}
		return &Polynomial{
			coefficients: coefficients,
			exponents:    exponents,
		}, nil
	}
}

func (poly *Polynomial) Private() bool {
	return poly.coefficients != nil
}

func (poly *Polynomial) Exponents() []*ed.Point {
	return poly.exponents
}

// Evaluate evaluates a polynomial in a given variable index
// We use Horner's method: https://en.wikipedia.org/wiki/Horner%27s_method
func (poly *Polynomial) Evaluate(x *ed.Scalar) (*ed.Scalar, error) {
	// throw error if the x is Zero as it is considered as an attempt to leak secret
	if x == nil || x.Equal(ed.NewScalar()) == 1 {
		return nil, errors.New("polynomial: attempt to leak secret")
	}

	// throw error if the polynomial contains only exponents
	if !poly.Private() {
		return nil, errors.New("polynomial: contains only exponents, cannot evaluate coefficients")
	}

	result := ed.NewScalar()
	for i := len(poly.coefficients) - 1; i >= 0; i-- {
		result.MultiplyAdd(result, x, poly.coefficients[i])
	}
	return result, nil
}

func (poly *Polynomial) EvaluateExponent(x *ed.Scalar) (*ed.Point, error) {
	// throw error if the x is Zero as it is considered as an attempt to leak secret
	if x == nil || x.Equal(ed.NewScalar()) == 1 {
		return nil, errors.New("polynomial: attempt to leak secret")
	}

	result := new(ed.Point).Set(poly.exponents[len(poly.exponents)-1])
	for i := len(poly.exponents) - 2; i >= 0; i-- {
		result = result.ScalarMult(x, result).Add(result, poly.exponents[i])
	}

	return result, nil
}

func (poly *Polynomial) Constant() *ed.Point {
	return poly.exponents[0]
}

func (poly *Polynomial) Degree() int {
	return len(poly.exponents) - 1
}

func (poly *Polynomial) MarshalBinary() ([]byte, error) {
	data := make([]byte, 0)

	// 1. Degree
	data = append(data, byte(poly.Degree()))

	// 2. Coefficients
	if poly.Private() {
		for i := 0; i <= int(poly.Degree()); i++ {
			cb := poly.coefficients[i].Bytes()
			eb := poly.exponents[i].Bytes()
			data = append(data, cb...)
			data = append(data, eb...)
		}
	} else {
		for i := 0; i <= int(poly.Degree()); i++ {
			eb := poly.exponents[i].Bytes()
			data = append(data, eb...)
		}
	}

	return data, nil
}

func (p *Polynomial) UnmarshalBinary(data []byte) error {
	if len(data) == 0 {
		return errors.New("polynomial: invalid input data")
	}

	// 1. Degree
	degree := int(data[0])

	// 2. Coefficients
	offset := 1
	if len(data) == 1+(degree+1)*(CoefficientSize+ExponentSize) {
		p.coefficients = make([]*ed.Scalar, degree+1)
		p.exponents = make([]*ed.Point, degree+1)
		for i := 0; i <= degree; i++ {
			cb := data[offset : offset+CoefficientSize]
			eb := data[offset+CoefficientSize : offset+CoefficientSize+ExponentSize]
			c, err := ed.NewScalar().SetCanonicalBytes(cb)
			if err != nil {
				return errors.WithMessage(err, "polynomial: failed to unmarshal coefficient")
			}
			e, err := (&ed.Point{}).SetBytes(eb)
			if err != nil {
				return errors.WithMessage(err, "polynomial: failed to unmarshal exponent")
			}
			if e.Equal((&ed.Point{}).ScalarBaseMult(c)) != 1 {
				return errors.New("polynomial: exponent doesn't match coefficient")
			}
			p.coefficients[i] = c
			p.exponents[i] = e
			offset += CoefficientSize + ExponentSize
		}
	} else if len(data) == 1+(degree+1)*ExponentSize {
		p.exponents = make([]*ed.Point, degree+1)
		for i := 0; i <= degree; i++ {
			eb := data[offset : offset+ExponentSize]
			e, err := (&ed.Point{}).SetBytes(eb)
			if err != nil {
				return errors.WithMessage(err, "polynomial: failed to unmarshal exponent")
			}
			p.exponents[i] = e
			offset += ExponentSize
		}
	} else {
		return errors.New("polynomial: invalid input data")
	}

	return nil
}
