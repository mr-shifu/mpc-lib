package mta

import (
	"github.com/cronokirby/saferith"
	comm_mta "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/mta"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
)

type MtAManager struct {
	store keystore.Keystore
}

func NewMtAManager(store keystore.Keystore) *MtAManager {
	return &MtAManager{
		store: store,
	}
}

func (m *MtAManager) Get(keyID string) (comm_mta.MtA, error) {
	b, err := m.store.Get(keyID)
	if err != nil {
		return nil, err
	}
	return fromBytes(b)
}

func (m *MtAManager) Import(keyID string, key comm_mta.MtA) error {
	b, err := key.Bytes()
	if err != nil {
		return err
	}
	err = m.store.Import(keyID, b)
	if err != nil {
		return err
	}
	return nil
}

func (m *MtAManager) SetAlpha(keyID string, alpha *saferith.Int) error {
	mta, err := m.Get(keyID)
	if err != nil {
		return err
	}
	mta.SetAlpha(alpha)
	return m.Import(keyID, mta)
}

func (m *MtAManager) SetBeta(keyID string, beta *saferith.Int) error {
	mta, err := m.Get(keyID)
	if err != nil {
		return err
	}
	mta.SetBeta(beta)
	return m.Import(keyID, mta)
}
