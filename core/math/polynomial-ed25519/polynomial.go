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
func NewPolynomial(degree int, constant *ed.Scalar) (*Polynomial, error) {
	polynomial := &Polynomial{
		coefficients: make([]*ed.Scalar, degree+1),
		exponents:    make([]*ed.Point, degree+1),
	}

	// if the constant is nil, we interpret it as 0.
	if constant == nil {
		constant = ed.NewScalar()
	}
	if constant.Equal(ed.NewScalar()) == 1 {
		return nil, errors.New("polynomial: invalid constant")
	}
	polynomial.coefficients[0] = constant

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

func (poly *Polynomial) Private() bool {
	return poly.coefficients == nil
}

func (poly *Polynomial) Exponents() []*ed.Point {
	return poly.exponents
}

// Evaluate evaluates a polynomial in a given variable index
// We use Horner's method: https://en.wikipedia.org/wiki/Horner%27s_method
func (poly *Polynomial) Evaluate(x *ed.Scalar) (*ed.Scalar, error) {
	// throw error if the x is Zero as it is considered as an attempt to leak secret
	if x.Equal(ed.NewScalar()) == 1 {
		return nil, errors.New("polynomial: attempt to leak secret")
	}

	result := ed.NewScalar()
	// reverse order
	for i := len(poly.coefficients) - 1; i >= 0; i-- {
		// bₙ₋₁ = bₙ * x + aₙ₋₁
		result.MultiplyAdd(result, x, poly.coefficients[i])
	}
	return result, nil
}

func (poly *Polynomial) EvaluateExponent(x *ed.Scalar) *ed.Point {
	result := &ed.Point{}

	for i := len(poly.exponents) - 1; i >= 0; i-- {
		result = result.ScalarMult(x, result)
		result = result.Add(result, poly.exponents[i])
	}

	return result
}

func (poly *Polynomial) Constant() *ed.Scalar {
	return poly.coefficients[0]
}

func (poly *Polynomial) Degree() uint32 {
	return uint32(len(poly.exponents) - 1)
}

func (poly *Polynomial) MarshalBinary() ([]byte, error) {
	data := make([]byte, 0)

	// 1. Degree
	data = append(data, byte(poly.Degree()))

	// 2. Coefficients
	if poly.Private() {
		for i := 1; i <= int(poly.Degree()); i++ {
			cb := poly.coefficients[i].Bytes()
			eb := poly.exponents[i].Bytes()
			data = append(data, cb...)
			data = append(data, eb...)
		}
	} else {
		for i := 1; i <= int(poly.Degree()); i++ {
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
