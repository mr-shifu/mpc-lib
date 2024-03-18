package mta

import (
	"errors"

	"github.com/cronokirby/saferith"
	"github.com/google/uuid"
	comm_mta "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/mta"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyrepository"
	mpc_mta "github.com/mr-shifu/mpc-lib/pkg/mpc/common/mta"
)

type PaillierEncodedKeyManager struct {
	km comm_mta.MtAManager
	kr keyrepository.KeyRepository
}

func NewPaillierKeyManager(km comm_mta.MtAManager, kr keyrepository.KeyRepository) mpc_mta.MtAManager {
	return &PaillierEncodedKeyManager{km, kr}
}

func (mgr *PaillierEncodedKeyManager) ImportKey(keyID string, partyID string, k comm_mta.MtA) (comm_mta.MtA, error) {
	kid := uuid.New().String()
	
	if err := mgr.km.Import(kid, k); err != nil {
		return nil, err
	}

	if err := mgr.kr.Import(keyID, keyrepository.KeyData{
		PartyID: partyID,
		SKI:     []byte(kid),
	}); err != nil {
		return nil, err
	}

	return k, nil
}

func (mgr *PaillierEncodedKeyManager) GetKey(keyID string, partyID string) (comm_mta.MtA, error) {
	keys, err := mgr.kr.GetAll(keyID)
	if err != nil {
		return nil, err
	}

	k, ok := keys[partyID]
	if !ok {
		return nil, errors.New("key not found")
	}

	return mgr.km.Get(string(k.SKI))
}

func (mgr *PaillierEncodedKeyManager) SetAlpha(keyID string, partyID string, alpha *saferith.Int) error {
	keys, err := mgr.kr.GetAll(keyID)
	if err != nil {
		return  err
	}

	k, ok := keys[partyID]
	if !ok {
		return errors.New("key not found")
	}

	return mgr.km.SetAlpha(string(k.SKI), alpha)
}

func (mgr *PaillierEncodedKeyManager) SetBeta(keyID string, partyID string, beta *saferith.Int) error {
	keys, err := mgr.kr.GetAll(keyID)
	if err != nil {
		return  err
	}

	k, ok := keys[partyID]
	if !ok {
		return errors.New("key not found")
	}

	return mgr.km.SetBeta(string(k.SKI), beta)
}
