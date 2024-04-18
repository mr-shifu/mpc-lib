package result

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
)

type EddsaSignatureManager struct {
	ks *InMemoryEddsaSignature
}

func NewEddsaSignatureManager(ks *InMemoryEddsaSignature) *EddsaSignatureManager {
	return &EddsaSignatureManager{
		ks: ks,
	}
}

func (m *EddsaSignatureManager) NewEddsaSignature(r curve.Point, z curve.Scalar) *EddsaSignature {
	return NewEddsaSignature(r, z)
}

func (m *EddsaSignatureManager) Import(sig *EddsaSignature, opts keyopts.Options) error {
	return m.ks.Import(sig, opts)
}

func (m *EddsaSignatureManager) SetR(R curve.Point, opts keyopts.Options) error {
	sig, err := m.ks.Get(opts)
	if err != nil {
		return err
	}
	sig.SetR(R)
	return m.ks.Import(sig, opts)
}

func (m *EddsaSignatureManager) SetZ(z curve.Scalar, opts keyopts.Options) error {
	sig, err := m.ks.Get(opts)
	if err != nil {
		return err
	}
	sig.SetZ(z)
	return m.ks.Import(sig, opts)
}

func (m *EddsaSignatureManager) Get(opts keyopts.Options) (*EddsaSignature, error) {
	return m.ks.Get(opts)
}
