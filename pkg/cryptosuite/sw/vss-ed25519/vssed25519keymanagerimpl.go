package vssed25519

import (
	"encoding/hex"

	ed "filippo.io/edwards25519"
	"github.com/mr-shifu/mpc-lib/core/math/polynomial-ed25519"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
	"github.com/pkg/errors"
)

type VssKeyManagerImpl struct {
	ks keystore.Keystore
}

func NewVssKeyManager(ks keystore.Keystore) *VssKeyManagerImpl {
	return &VssKeyManagerImpl{
		ks: ks,
	}
}

// GenerateSecrets generates a Polynomail of a specified degree with secret as constant value
// and stores coefficients and expponents of coefficients.
func (mgr *VssKeyManagerImpl) GenerateSecrets(secret *ed.Scalar, degree int, opts keyopts.Options) (VssKey, error) {
	// Generate a polynomial with secret as constant value
	poly, err := polynomial.GeneratePolynomial(degree, secret)
	if err != nil {
		return nil, errors.WithMessage(err, "vss: failed to generate polynomial")
	}

	// get SKI from binary encoded exponents
	vssKey := NewVssKey(poly)
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

	return vssKey, nil
}

// ImportSecrets imports exponents of coefficients and returns VssKey.
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
		kb, err := kt.Bytes()
		if err != nil {
			return nil, err
		}

		// get SKI from binary encoded exponents
		ski := kt.SKI()
		keyID := hex.EncodeToString(ski)

		// store coefficients and exponents in keystore
		if err := mgr.ks.Import(keyID, kb, opts); err != nil {
			return nil, err
		}

		return kt, nil
	default:
		return nil, errors.New("vss: invalid key type")
	}
}

// GetSecrets returns VssKey of coefficients.
func (mgr *VssKeyManagerImpl) GetSecrets(opts keyopts.Options) (VssKey, error) {
	vb, err := mgr.ks.Get(opts)
	if err != nil {
		return nil, errors.WithMessage(err, "vss: failed to get key")
	}

	k := new(VssKeyImpl)
	if err := k.FromBytes(vb); err != nil {
		return nil, errors.WithMessage(err, "vss: failed to unmarshal key")
	}

	return k, nil
}

func (mgr *VssKeyManagerImpl) DeleteSecrets(opts keyopts.Options) error {
	return mgr.ks.Delete(opts)
}

func (mgr *VssKeyManagerImpl) DeleteAllSecrets(opts keyopts.Options) error {
	return mgr.ks.DeleteAll(opts)
}

// Evaluate evaluates polynomial at a scalar using coefficients.
func (mgr *VssKeyManagerImpl) Evaluate(index *ed.Scalar, opts keyopts.Options) (*ed.Scalar, error) {
	k, err := mgr.GetSecrets(opts)
	if err != nil {
		return nil, err
	}

	key, ok := k.(*VssKeyImpl)
	if !ok {
		return nil, errors.New("vss: invalid key")
	}

	return key.Evaluate(index)
}

// EvaluateByExponents evaluates polynomial using exponents of coefficients.
func (mgr *VssKeyManagerImpl) EvaluateByExponents(index *ed.Scalar, opts keyopts.Options) (*ed.Point, error) {
	k, err := mgr.GetSecrets(opts)
	if err != nil {
		return nil, err
	}

	key, ok := k.(*VssKeyImpl)
	if !ok {
		return nil, errors.New("vss: invalid key")
	}

	return key.EvaluateByExponents(index)
}

func (mgr *VssKeyManagerImpl) SumExponents(optsList ...keyopts.Options) (VssKey, error) {
	// get coefficients from keystore
	polys := make([]*polynomial.Polynomial, len(optsList))
	for i, opts := range optsList {
		k, err := mgr.GetSecrets(opts)
		if err != nil {
			return nil, err
		}

		key, ok := k.(*VssKeyImpl)
		if !ok {
			return nil, errors.New("vss: invalid key")
		}

		polys[i] = key.poly
	}

	// sum exponents of coefficients
	sum, err := new(polynomial.Polynomial).Sum(polys)
	if err != nil {
		return nil, errors.WithMessage(err, "vss: failed to sum exponents")
	}

	return NewVssKey(sum), nil
}
