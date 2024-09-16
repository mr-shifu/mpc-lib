package ecdsa

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/result"
)

type EcdsaSignatureManager struct {
	ks *InMemoryEcdsaSignature
}

var _ result.EcdsaSignatureManager = (*EcdsaSignatureManager)(nil)

func NewEcdsaSignatureManager(ks *InMemoryEcdsaSignature) result.EcdsaSignatureManager {
	return &EcdsaSignatureManager{
		ks: ks,
	}
}

func (m *EcdsaSignatureManager) NewEcdsaSignature(r curve.Point, sigma curve.Scalar) result.EcdsaSignature {
	return NewEcdsaSignature(r, sigma)
}


func (m *EcdsaSignatureManager) Import(sig result.EcdsaSignature, opts keyopts.Options) error {
	return m.ks.Import(sig, opts)
}

func (m *EcdsaSignatureManager) SetR(R curve.Point, opts keyopts.Options) error {
	sig, err := m.ks.Get(opts)
	if err != nil {
		return err
	}
	sig.SetR(R)
	return m.ks.Import(sig, opts)
}

func (m *EcdsaSignatureManager) SetSigma(z curve.Scalar, opts keyopts.Options) error {
	sig, err := m.ks.Get(opts)
	if err != nil {
		return err
	}
	sig.SetSigma(z)
	return m.ks.Import(sig, opts)
}

func (m *EcdsaSignatureManager) Get(opts keyopts.Options) (result.EcdsaSignature, error) {
	return m.ks.Get(opts)
}
