package mta

import (
	"github.com/cronokirby/saferith"
	"github.com/google/uuid"
	comm_mta "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/mta"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
)

type MtAManager struct {
	store keystore.Keystore
}

func NewMtAManager(store keystore.Keystore) *MtAManager {
	return &MtAManager{
		store: store,
	}
}

func (m *MtAManager) Get(opts keyopts.Options) (comm_mta.MtA, error) {
	b, err := m.store.Get(opts)
	if err != nil {
		return nil, err
	}
	return fromBytes(b)
}

func (m *MtAManager) Import(key comm_mta.MtA, opts keyopts.Options) error {
	b, err := key.Bytes()
	if err != nil {
		return err
	}
	keyID := uuid.New().String()
	err = m.store.Import(keyID, b, opts)
	if err != nil {
		return err
	}
	return nil
}

func (m *MtAManager) SetAlpha(alpha *saferith.Int, opts keyopts.Options) error {
	mta, err := m.Get(opts)
	if err != nil || mta == nil {
		mta = NewMtA(alpha, nil)
	} else {
		mta.SetAlpha(alpha)
	}
	mb, err := mta.Bytes()
	if err != nil {
		return err
	}
	return m.store.Update(mb, opts)
}

func (m *MtAManager) SetBeta(beta *saferith.Int, opts keyopts.Options) error {
	mta, err := m.Get(opts)
	if err != nil || mta == nil {
		mta = NewMtA(beta, nil)
	} else {
		mta.SetBeta(beta)
	}
	mb, err := mta.Bytes()
	if err != nil {
		return err
	}
	return m.store.Update(mb, opts)
}
