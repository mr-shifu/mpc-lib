package vss

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/mr-shifu/mpc-lib/core/math/polynomial"
)

type VssKey struct {
	secrets   *polynomial.Polynomial
	exponents *polynomial.Exponent
}

func NewVssKey(secrets *polynomial.Polynomial, exponents *polynomial.Exponent) VssKey {
	return VssKey{
		secrets:   secrets,
		exponents: exponents,
	}
}

// Bytes returns the byte representation of the vss coefficients.
func (k VssKey) Bytes() ([]byte, error) {
	sb, err := k.secrets.MarshalBinary()
	if err != nil {
		return nil, err
	}

	eb, err := k.exponents.MarshalBinary()
	if err != nil {
		return nil, err
	}

	slb := make([]byte, 2)
	binary.LittleEndian.PutUint16(slb, uint16(len(sb)))

	elb := make([]byte, 2)
	binary.LittleEndian.PutUint16(elb, uint16(len(eb)))

	buf := make([]byte, 0)
	buf = append(buf, slb...)
	buf = append(buf, sb...)
	buf = append(buf, elb...)
	buf = append(buf, eb...)

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
func (k VssKey) Exponents() (VssKey, error) {
	if k.exponents == nil {
		return VssKey{}, errors.New("no exponents")
	}
	return VssKey{
		exponents: k.exponents,
	}, nil
}

func fromBytes(data []byte) (VssKey, error) {
	// read secrets length
	secretsLen := binary.LittleEndian.Uint16(data[:2])
	secrets := &polynomial.Polynomial{}
	if err := secrets.UnmarshalBinary(data[2 : secretsLen+2]); err != nil {
		return VssKey{}, err
	}

	// read exponents length
	exponentsLen := binary.LittleEndian.Uint16(data[secretsLen+2 : secretsLen+4])
	exponents := &polynomial.Exponent{}
	if err := exponents.UnmarshalBinary(data[secretsLen+4 : secretsLen+4+exponentsLen]); err != nil {
		return VssKey{}, err
	}

	return VssKey{
		secrets:   secrets,
		exponents: exponents,
	}, nil
}
