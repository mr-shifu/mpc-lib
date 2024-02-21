package vss

import (
	"encoding/hex"
	"errors"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/math/polynomial"
	cs_vss "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/vss"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
)

type VssKeyManager struct {
	group curve.Curve
	ks    keystore.Keystore
}

func NewVssKeyManager(store keystore.Keystore, g curve.Curve) *VssKeyManager {
	return &VssKeyManager{
		group: g,
		ks:    store,
	}
}

// GenerateSecrets generates a Polynomail of a specified degree with secret as constant value
// and stores coefficients and expponents of coefficients.
func (mgr *VssKeyManager) GenerateSecrets(secret curve.Scalar, degree int) (cs_vss.VssKey, error) {
	// Generate a polynomial with secret as constant value
	secrets := polynomial.NewPolynomial(mgr.group, degree, secret)
	// Generate exponents of coefficients
	exponents := polynomial.NewPolynomialExponent(secrets)

	// get SKI from binary encoded exponents
	ski, err := exponents.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// encode ski to hex string as keyID
	keyID := hex.EncodeToString(ski)

	// encode secrets to binary
	vb, err := secrets.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// store coefficients and exponents in keystore
	if err = mgr.ks.Import(keyID, vb); err != nil {
		return nil, err
	}

	return VssKey{secrets, exponents}, nil
}

// ImportSecrets imports exponents of coefficients and returns VssKey.
func (mgr *VssKeyManager) ImportSecrets(exponents *polynomial.Exponent) (cs_vss.VssKey, error) {
	// get SKI from binary encoded exponents
	ski, err := exponents.MarshalBinary()
	if err != nil {
		return VssKey{}, err
	}

	// encode ski to hex string as keyID
	keyID := hex.EncodeToString(ski)

	// get coefficients from keystore
	key := NewVssKey(nil, exponents)

	// decode binary to polynomial
	kb, err := key.Bytes()
	if err != nil {
		return VssKey{}, err
	}

	// store coefficients and exponents in keystore
	if err = mgr.ks.Import(keyID, kb); err != nil {
		return VssKey{}, err
	}

	return key, nil
}

// GetSecrets returns VssKey of coefficients.
func (mgr *VssKeyManager) GetSecrets(ski []byte) (cs_vss.VssKey, error) {
	// encode ski to hex string as keyID
	keyID := hex.EncodeToString(ski)

	// get coefficients from keystore
	vb, err := mgr.ks.Get(keyID)
	if err != nil {
		return VssKey{}, err
	}

	// decode binary to polynomial
	return fromBytes(vb)
}

// Evaluate evaluates polynomial at a scalar using coefficients.
func (mgr *VssKeyManager) Evaluate(ski []byte, index curve.Scalar) (curve.Scalar, error) {
	// get coefficients from keystore
	k, err := mgr.GetSecrets(ski)
	if err != nil {
		return nil, err
	}

	key, ok := k.(*VssKey)
	if !ok {
		return nil, errors.New("invalid key")
	}

	// evaluate polynomial at a scalar using coefficients
	return key.secrets.Evaluate(index), nil
}

// EvaluateByExponents evaluates polynomial using exponents of coefficients.
func (mgr *VssKeyManager) EvaluateByExponents(ski []byte, index curve.Scalar) (curve.Point, error) {
	// get coefficients from keystore
	k, err := mgr.GetSecrets(ski)
	if err != nil {
		return nil, err
	}

	key, ok := k.(*VssKey)
	if !ok {
		return nil, errors.New("invalid key")
	}

	// evaluate polynomial using exponents of coefficients
	return key.exponents.Evaluate(index), nil
}
