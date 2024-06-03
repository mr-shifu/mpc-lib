package result

import (
	"filippo.io/edwards25519"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/result"
)

type EddsaSignatureManager struct {
	ks *InMemoryEddsaSignature
}

func NewEddsaSignatureManager(ks *InMemoryEddsaSignature) result.EddsaSignatureManager {
	return &EddsaSignatureManager{
		ks: ks,
	}
}

func (m *EddsaSignatureManager) NewEddsaSignature(r *edwards25519.Point, z *edwards25519.Scalar) result.EddsaSignature {
	return NewEddsaSignature(r, z)
}

func (m *EddsaSignatureManager) Import(sig result.EddsaSignature, opts keyopts.Options) error {
	return m.ks.Import(sig, opts)
}

func (m *EddsaSignatureManager) SetR(R *edwards25519.Point, opts keyopts.Options) error {
	sig, err := m.ks.Get(opts)
	if err != nil {
		return err
	}
	sig.SetR(R)
	return m.ks.Import(sig, opts)
}

func (m *EddsaSignatureManager) SetZ(z *edwards25519.Scalar, opts keyopts.Options) error {
	sig, err := m.ks.Get(opts)
	if err != nil {
		return err
	}
	sig.SetZ(z)
	return m.ks.Import(sig, opts)
}

func (m *EddsaSignatureManager) Get(opts keyopts.Options) (result.EddsaSignature, error) {
	return m.ks.Get(opts)
}
