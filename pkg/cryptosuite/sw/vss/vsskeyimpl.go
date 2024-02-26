package vss

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/math/polynomial"
	cs_vss "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/vss"
)

type VssKey struct {
	secrets   *polynomial.Polynomial
	exponents *polynomial.Exponent
}

func NewVssKey(secrets *polynomial.Polynomial, exponents *polynomial.Exponent) cs_vss.VssKey {
	return VssKey{
		secrets:   secrets,
		exponents: exponents,
	}
}

// Bytes returns the byte representation of the vss coefficients.
func (k VssKey) Bytes() ([]byte, error) {
	gn := k.exponents.Group().Name()
	gnl := len(gn)

	eb, err := k.exponents.MarshalBinary()
	if err != nil {
		return nil, err
	}
	elb := make([]byte, 2)
	binary.LittleEndian.PutUint16(elb, uint16(len(eb)))

	buf := make([]byte, 0)
	buf = append(buf, byte(gnl))
	buf = append(buf, gn...)
	buf = append(buf, elb...)
	buf = append(buf, eb...)

	if k.Private() {
		sb, err := k.secrets.MarshalBinary()
		if err != nil {
			return nil, err
		}
		slb := make([]byte, 2)
		binary.LittleEndian.PutUint16(slb, uint16(len(sb)))

		buf = append(buf, slb...)
		buf = append(buf, sb...)
	}

	return buf, nil
}

// SKI returns the serialized key identifier.
func (k VssKey) SKI() []byte {
	kbs, err := k.exponents.MarshalBinary()
	if err != nil {
		return nil
	}
	hash := sha256.New()
	hash.Write(kbs)
	return hash.Sum(nil)
}

// Private returns true if the key is private.
func (k VssKey) Private() bool {
	return k.secrets != nil
}

// PublicKey returns the corresponding Exponents of coefficients.
func (k VssKey) Exponents() (cs_vss.VssKey, error) {
	if k.exponents == nil {
		return VssKey{}, errors.New("no exponents")
	}
	return VssKey{
		exponents: k.exponents,
	}, nil
}

func (k VssKey) ExponentsRaw() (*polynomial.Exponent, error) {
	if k.exponents == nil {
		return nil, errors.New("no exponents")
	}
	return k.exponents, nil
}

// Evaluate evaluates polynomial at a scalar using coefficients.
func (k VssKey) Evaluate(index curve.Scalar) (curve.Scalar, error) {
	// evaluate polynomial at a scalar using coefficients
	return k.secrets.Evaluate(index), nil
}

// EvaluateByExponents evaluates polynomial using exponents of coefficients.
func (k VssKey) EvaluateByExponents(index curve.Scalar) (curve.Point, error) {
	// evaluate polynomial using exponents of coefficients
	return k.exponents.Evaluate(index), nil
}

func fromBytes(data []byte) (VssKey, error) {
	// read group
	gnlen := uint16(data[0])
	gn := string(data[1 : 1+gnlen])
	var group curve.Curve
	if gn == "secp256k1" {
		group = curve.Secp256k1{}
	} else {
		return VssKey{}, errors.New("unsupported curve")
	}

	// read exponents length
	exponentsLen := binary.LittleEndian.Uint16(data[1+gnlen : 1+gnlen+2])
	exponents := polynomial.EmptyExponent(group)
	if err := exponents.UnmarshalBinary(data[1+gnlen+2 : 1+gnlen+2+exponentsLen]); err != nil {
		return VssKey{}, err
	}

	// read secrets length
	secretsLen := binary.LittleEndian.Uint16(data[1+gnlen+2+exponentsLen : 1+gnlen+2+exponentsLen+2])
	if secretsLen == 0 {
		return VssKey{
			secrets:   nil,
			exponents: exponents,
		}, nil

	}
	secrets := polynomial.NewEmptyPolynomial(group, exponents.Degree())
	if err := secrets.UnmarshalBinary(data[1+gnlen+2+exponentsLen+2 : 1+gnlen+2+exponentsLen+2+secretsLen]); err != nil {
		return VssKey{}, err
	}

	return VssKey{
		secrets:   secrets,
		exponents: exponents,
	}, nil
}
