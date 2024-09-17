package vss

import (
	"encoding/hex"
	"errors"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/math/polynomial"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
)

type VssKeyManagerImpl struct {
	group curve.Curve
	ks    keystore.Keystore
}

func NewVssKeyManager(store keystore.Keystore, g curve.Curve) *VssKeyManagerImpl {
	return &VssKeyManagerImpl{
		group: g,
		ks:    store,
	}
}

// GenerateSecrets generates a Polynomail of a specified degree with secret as constant value
// and stores coefficients and expponents of coefficients.
func (mgr *VssKeyManagerImpl) GenerateSecrets(secret curve.Scalar, degree int, opts keyopts.Options) (VssKey, error) {
	// Generate a polynomial with secret as constant value
	secrets := polynomial.NewPolynomial(mgr.group, degree, secret)
	// Generate exponents of coefficients
	exponents := polynomial.NewPolynomialExponent(secrets)

	// get SKI from binary encoded exponents
	vssKey := NewVssKey(secrets, exponents)
	ski := vssKey.SKI()

	// encode ski to hex string as keyID
	keyID := hex.EncodeToString(ski)

	// encode secrets to binary
	vb, err := vssKey.Bytes()
	if err != nil {
		return nil, err
	}

	// store coefficients and exponents in keystore
	if err = mgr.ks.Import(keyID, vb, opts); err != nil {
		return nil, err
	}

	// create a linked sharestore and set it in vssKey
	// sharestore, err := mgr.st.WithSKI(ski)
	// if err != nil {
	// 	return nil, err
	// }
	// vssKey.WithShareStore(sharestore)

	return vssKey, nil
}

// ImportSecrets imports exponents of coefficients in []byte format and returns VssKey.
func (mgr *VssKeyManagerImpl) ImportSecrets(key any, opts keyopts.Options) (VssKey, error) {
	switch kt := key.(type) {
	case []byte:
		k := new(VssKeyImpl)
		if err := k.FromBytes(kt); err != nil {
			return nil, err
		}

		// get SKI from binary encoded exponents
		ski := k.SKI()
		keyID := hex.EncodeToString(ski)

		// store coefficients and exponents in keystore
		if err := mgr.ks.Import(keyID, kt, opts); err != nil {
			return nil, err
		}

		return k, nil

	case VssKey:
		// get SKI from binary encoded exponents
		ski := kt.SKI()

		// encode ski to hex string as keyID
		keyID := hex.EncodeToString(ski)

		// decode binary to polynomial
		kb, err := kt.Bytes()
		if err != nil {
			return nil, err
		}

		// store coefficients and exponents in keystore
		if err = mgr.ks.Import(keyID, kb, opts); err != nil {
			return nil, err
		}

		return kt, nil

	default:
		return nil, errors.New("vss: invalid key type")
	}

}

// GetSecrets returns VssKey of coefficients.
func (mgr *VssKeyManagerImpl) GetSecrets(opts keyopts.Options) (VssKey, error) {
	// get coefficients from keystore
	vb, err := mgr.ks.Get(opts)
	if err != nil {
		return nil, err
	}

	// decode binary to polynomial
	vssKey := new(VssKeyImpl)
	err = vssKey.FromBytes(vb)
	if err != nil {
		return nil, err
	}

	return vssKey, nil
}

func (mgr *VssKeyManagerImpl) DeleteSecrets(opts keyopts.Options) error {
	return mgr.ks.Delete(opts)
}

func (mgr *VssKeyManagerImpl) DeleteAllSecrets(opts keyopts.Options) error {
	return mgr.ks.DeleteAll(opts)
}

// Evaluate evaluates polynomial at a scalar using coefficients.
func (mgr *VssKeyManagerImpl) Evaluate(index curve.Scalar, opts keyopts.Options) (curve.Scalar, error) {
	// get coefficients from keystore
	k, err := mgr.GetSecrets(opts)
	if err != nil {
		return nil, err
	}

	key, ok := k.(*VssKeyImpl)
	if !ok {
		return nil, errors.New("invalid key")
	}

	// evaluate polynomial at a scalar using coefficients
	return key.secrets.Evaluate(index), nil
}

// EvaluateByExponents evaluates polynomial using exponents of coefficients.
func (mgr *VssKeyManagerImpl) EvaluateByExponents(index curve.Scalar, opts keyopts.Options) (curve.Point, error) {
	// get coefficients from keystore
	k, err := mgr.GetSecrets(opts)
	if err != nil {
		return nil, err
	}

	key, ok := k.(*VssKeyImpl)
	if !ok {
		return nil, errors.New("invalid key")
	}

	// evaluate polynomial using exponents of coefficients
	return key.exponents.Evaluate(index), nil
}

func (mgr *VssKeyManagerImpl) SumExponents(optsList ...keyopts.Options) (VssKey, error) {
	var allExponents []*polynomial.Exponent
	for _, opts := range optsList {
		vssKey, err := mgr.GetSecrets(opts)
		if err != nil {
			return nil, err
		}
		exp, err := vssKey.ExponentsRaw()
		if err != nil {
			return nil, err
		}
		allExponents = append(allExponents, exp)
	}
	summed, err := polynomial.Sum(allExponents)
	if err != nil {
		return nil, err
	}

	return NewVssKey(nil, summed), nil
}
