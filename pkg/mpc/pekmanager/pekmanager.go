package pekmanager

import (
	"errors"

	"github.com/google/uuid"
	comm_pek "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/paillierencodedkey"
	mpc_pek "github.com/mr-shifu/mpc-lib/pkg/mpc/common/pek"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyrepository"
)

type PaillierEncodedKeyManager struct {
	km comm_pek.PaillierEncodedKeyManager
	kr keyrepository.KeyRepository
}

func NewPaillierKeyManager(km comm_pek.PaillierEncodedKeyManager, kr keyrepository.KeyRepository) mpc_pek.PaillierEncodedKeyManager {
	return &PaillierEncodedKeyManager{km, kr}
}

func (mgr *PaillierEncodedKeyManager) ImportKey(keyID string, partyID string, k comm_pek.PaillierEncodedKey) (comm_pek.PaillierEncodedKey, error) {
	kid := uuid.New().String()

	if _, err := mgr.km.Import(kid, k); err != nil {
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

func (mgr *PaillierEncodedKeyManager) GetKey(keyID string, partyID string) (comm_pek.PaillierEncodedKey, error) {
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
