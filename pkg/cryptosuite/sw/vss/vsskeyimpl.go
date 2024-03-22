package vss

import (
	"crypto/sha256"
	"errors"

	"github.com/fxamacker/cbor/v2"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/math/polynomial"
	cs_vss "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/vss"
)

type VssKey struct {
	secrets   *polynomial.Polynomial
	exponents *polynomial.Exponent
}

type rawVssKey struct {
	Group     string
	Secrets   []byte
	Exponents []byte
}

func NewVssKey(secrets *polynomial.Polynomial, exponents *polynomial.Exponent) cs_vss.VssKey {
	return &VssKey{
		secrets:   secrets,
		exponents: exponents,
	}
}

// Bytes returns the byte representation of the vss coefficients.
func (k *VssKey) Bytes() ([]byte, error) {
	raw := rawVssKey{}

	if k.exponents != nil {
		gn := k.exponents.Group().Name()
		exponents_bytes, err := k.exponents.MarshalBinary()
		if err != nil {
			return nil, err
		}
		raw.Group = gn
		raw.Exponents = exponents_bytes
	}

	if k.secrets != nil {
		secrets_bytes, err := k.secrets.MarshalBinary()
		if err != nil {
			return nil, err
		}
		raw.Secrets = secrets_bytes
	}

	buf, err := cbor.Marshal(raw)

	return buf, err
}

// SKI returns the serialized key identifier.
func (k *VssKey) SKI() []byte {
	pub := k.exponents.Constant()
	pub_bytes, err := pub.MarshalBinary()
	if err != nil {
		return nil
	}
	hash := sha256.New()
	hash.Write(pub_bytes)
	return hash.Sum(nil)
}

// Private returns true if the key is private.
func (k *VssKey) Private() bool {
	return k.secrets != nil
}

// PublicKey returns the corresponding Exponents of coefficients.
func (k *VssKey) Exponents() (cs_vss.VssKey, error) {
	if k.exponents == nil {
		return nil, errors.New("no exponents")
	}
	return &VssKey{
		exponents: k.exponents,
	}, nil
}

func (k *VssKey) ExponentsRaw() (*polynomial.Exponent, error) {
	if k.exponents == nil {
		return nil, errors.New("no exponents")
	}
	return k.exponents, nil
}

// Evaluate evaluates polynomial at a scalar using coefficients.
func (k *VssKey) Evaluate(index curve.Scalar) (curve.Scalar, error) {
	// evaluate polynomial at a scalar using coefficients
	return k.secrets.Evaluate(index), nil
}

// EvaluateByExponents evaluates polynomial using exponents of coefficients.
func (k *VssKey) EvaluateByExponents(index curve.Scalar) (curve.Point, error) {
	// evaluate polynomial using exponents of coefficients
	return k.exponents.Evaluate(index), nil
}

func fromBytes(data []byte) (VssKey, error) {
	raw := &rawVssKey{}
	err := cbor.Unmarshal(data, raw)
	if err != nil {
		return VssKey{}, err
	}

	var group curve.Curve
	switch raw.Group {
	case "secp256k1":
		group = curve.Secp256k1{}
	}

	vss := VssKey{}

	if raw.Exponents != nil {
		exponents := polynomial.EmptyExponent(group)
		err = exponents.UnmarshalBinary(raw.Exponents)
		if err != nil {
			return VssKey{}, err
		}
		vss.exponents = exponents
	}

	if raw.Secrets != nil {
		secrets := &polynomial.Polynomial{}
		err = secrets.UnmarshalBinary(raw.Secrets)
		if err != nil {
			return VssKey{}, err
		}
		vss.secrets = secrets
	}

	return vss, nil
}
