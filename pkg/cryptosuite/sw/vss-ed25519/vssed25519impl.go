package vssed25519

import (
	"crypto/sha256"

	ed "filippo.io/edwards25519"
	"github.com/mr-shifu/mpc-lib/core/math/polynomial-ed25519"
	"github.com/pkg/errors"
)

type VssKeyImpl struct {
	poly *polynomial.Polynomial
}

func GenerateVssKey(degree int, constant *ed.Scalar) (VssKey, error) {
	poly, err := polynomial.GeneratePolynomial(degree, constant)
	if err != nil {
		return nil, errors.WithMessage(err, "vss: failed to generate polynomial")
	}
	return NewVssKey(poly), nil
}

func NewVssKey(poly *polynomial.Polynomial) VssKey {
	return &VssKeyImpl{
		poly: poly,
	}
}

// Bytes returns the byte representation of the vss coefficients.
func (k *VssKeyImpl) Bytes() ([]byte, error) {
	return k.poly.MarshalBinary()
}

func (k *VssKeyImpl) FromBytes(data []byte) error {
	k.poly = new(polynomial.Polynomial)
	if err := k.poly.UnmarshalBinary(data); err != nil {
		return errors.Wrap(err, "vss: failed to unmarshal polynomial")
	}
	return nil
}

// SKI returns the serialized key identifier.
func (k *VssKeyImpl) SKI() []byte {
	pub, err := k.Exponents()
	if err != nil {
		return nil
	}
	pub_bytes, err := pub.Bytes()
	if err != nil {
		return nil
	}
	hash := sha256.New()
	hash.Write(pub_bytes)
	return hash.Sum(nil)
}

// Private returns true if the key is private.
func (k *VssKeyImpl) Private() bool {
	return k.poly.Private()
}

// Exponents returns the corresponding Exponents of coefficients.
func (k *VssKeyImpl) Exponents() (VssKey, error) {
	p, err := polynomial.NewPolynomial(k.poly.Degree(), nil, k.poly.Exponents())
	if err != nil {
		return nil, errors.WithMessage(err, "vss: failed to create polynomial")
	}
	return NewVssKey(p), nil
}

// ExponentsRaw returns the corresponding Raw Exponents of coefficients.
func (k *VssKeyImpl) ExponentsRaw() (*polynomial.Polynomial, error) {
	return polynomial.NewPolynomial(k.poly.Degree(), nil, k.poly.Exponents())
}

// Evaluate evaluates polynomial at a scalar using coefficients.
func (k *VssKeyImpl) Evaluate(index *ed.Scalar) (*ed.Scalar, error) {
	return k.poly.Evaluate(index)
}

// EvaluateByExponents evaluates polynomial using exponents of coefficients.
func (k *VssKeyImpl) EvaluateByExponents(index *ed.Scalar) (*ed.Point, error) {
	return k.poly.EvaluateExponent(index)
}
