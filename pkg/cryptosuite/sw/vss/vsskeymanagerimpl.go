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
func (mgr *VssKeyManagerImpl) ImportSecrets(key VssKey, opts keyopts.Options) (VssKey, error) {
	// if data == nil {
	// 	return nil, errors.New("invalid exponents")
	// }

	// exponents := polynomial.NewEmptyExponent(mgr.group)
	// if err := exponents.UnmarshalBinary(data); err != nil {
	// 	return nil, err
	// }

	// get coefficients from keystore
	// key := NewVssKey(nil, exponents)

	// get SKI from binary encoded exponents
	ski := key.SKI()

	// encode ski to hex string as keyID
	keyID := hex.EncodeToString(ski)

	// decode binary to polynomial
	kb, err := key.Bytes()
	if err != nil {
		return nil, err
	}

	// store coefficients and exponents in keystore
	if err = mgr.ks.Import(keyID, kb, opts); err != nil {
		return nil, err
	}

	// sharestore, err := mgr.st.WithSKI(ski)
	// if err != nil {
	// 	return nil, err
	// }
	// key.WithShareStore(sharestore)

	return key, nil
}

// GetSecrets returns VssKey of coefficients.
func (mgr *VssKeyManagerImpl) GetSecrets(opts keyopts.Options) (VssKey, error) {
	// encode ski to hex string as keyID
	// keyID := hex.EncodeToString(ski)

	// get coefficients from keystore
	vb, err := mgr.ks.Get(opts)
	if err != nil {
		return nil, err
	}

	// decode binary to polynomial
	vssKey, err := fromBytes(vb)
	if err != nil {
		return nil, err
	}
	// sharestore, err := mgr.st.WithSKI(ski)
	// if err != nil {
	// 	return nil, err
	// }
	// vssKey.WithShareStore(sharestore)

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
