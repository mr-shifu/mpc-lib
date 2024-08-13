package mta

import (
	"github.com/cronokirby/saferith"
	"github.com/google/uuid"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
)

type MtAManagerImpl struct {
	store keystore.Keystore
}

var _ MtAManager = (*MtAManagerImpl)(nil)

func NewMtAManager(store keystore.Keystore) *MtAManagerImpl {
	return &MtAManagerImpl{
		store: store,
	}
}

func (m *MtAManagerImpl) Get(opts keyopts.Options) (MtA, error) {
	b, err := m.store.Get(opts)
	if err != nil {
		return nil, err
	}
	return fromBytes(b)
}

func (m *MtAManagerImpl) Import(key MtA, opts keyopts.Options) error {
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

func (m *MtAManagerImpl) SetAlpha(alpha *saferith.Int, opts keyopts.Options) error {
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

func (m *MtAManagerImpl) SetBeta(beta *saferith.Int, opts keyopts.Options) error {
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
