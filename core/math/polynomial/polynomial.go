package polynomial

import (
	"crypto/rand"
	"errors"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
)

// Polynomial represents f(X) = a₀ + a₁⋅X + … + aₜ⋅Xᵗ.
type Polynomial struct {
	group        curve.Curve
	coefficients []curve.Scalar
}

// NewPolynomial generates a Polynomial f(X) = secret + a₁⋅X + … + aₜ⋅Xᵗ,
// with coefficients in ℤₚ, and degree t.
func NewPolynomial(group curve.Curve, degree int, constant curve.Scalar) *Polynomial {
	polynomial := &Polynomial{
		group:        group,
		coefficients: make([]curve.Scalar, degree+1),
	}

	// if the constant is nil, we interpret it as 0.
	if constant == nil {
		constant = group.NewScalar()
	}
	polynomial.coefficients[0] = constant

	for i := 1; i <= degree; i++ {
		polynomial.coefficients[i] = sample.Scalar(rand.Reader, group)
	}

	return polynomial
}

// Evaluate evaluates a polynomial in a given variable index
// We use Horner's method: https://en.wikipedia.org/wiki/Horner%27s_method
func (p *Polynomial) Evaluate(index curve.Scalar) curve.Scalar {
	if index.IsZero() {
		panic("attempt to leak secret")
	}

	result := p.group.NewScalar()
	// reverse order
	for i := len(p.coefficients) - 1; i >= 0; i-- {
		// bₙ₋₁ = bₙ * x + aₙ₋₁
		result.Mul(index).Add(p.coefficients[i])
	}
	return result
}

// Constant returns a reference to the constant coefficient of the polynomial.
func (p *Polynomial) Constant() curve.Scalar {
	return p.group.NewScalar().Set(p.coefficients[0])
}

// Degree is the highest power of the Polynomial.
func (p *Polynomial) Degree() uint32 {
	return uint32(len(p.coefficients)) - 1
}

func (p *Polynomial) MarshalBinary() ([]byte, error) {
	data := make([]byte, 0)

	// 1. Group name
	gn := p.group.Name()
	data = append(data, byte(len(gn)))
	data = append(data, gn...)

	// 2. Degree
	data = append(data, byte(p.Degree()))

	// 3. Coefficients
	for _, c := range p.coefficients {
		b, err := c.MarshalBinary()
		if err != nil {
			return nil, err
		}
		data = append(data, uint8(len(b)))
		data = append(data, b...)
	}

	return data, nil
}

func (p *Polynomial) UnmarshalBinary(data []byte) error {
	// 1. Group name
	gnlen := int(data[0])
	gn := string(data[1 : 1+gnlen])
	var group curve.Curve
	if gn == "secp256k1" {
		group = curve.Secp256k1{}
	} else {
		return errors.New("unsupported curve")
	}
	p.group = group

	// 2. Degree
	degree := int(data[1+gnlen])

	// 3. Coefficients
	p.coefficients = make([]curve.Scalar, degree+1)
	offset := 1 + gnlen + 1
	for i := 0; i <= degree; i++ {
		blen := int(data[offset])
		offset++
		c := group.NewScalar()
		if err := c.UnmarshalBinary(data[offset : offset+blen]); err != nil {
			return err
		}
		p.coefficients[i] = c
		offset += blen
	}

	return nil
}
