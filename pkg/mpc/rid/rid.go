package rid

import (
	"errors"

	comm_rid "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/rid"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyrepository"
)

type RIDKeyManager struct {
	km comm_rid.RIDManager
	kr keyrepository.KeyRepository
}

func NewRIDKeyManager(km comm_rid.RIDManager, kr keyrepository.KeyRepository) *RIDKeyManager {
	return &RIDKeyManager{km, kr}
}

func (e *RIDKeyManager) GenerateKey(keyID string, partyID string) (comm_rid.RID, error) {
	key, err := e.km.GenerateKey()
	if err != nil {
		return nil, err
	}
	if err := e.kr.Import(keyID, keyrepository.KeyData{
		PartyID: partyID,
		SKI:     key.SKI(),
	}); err != nil {
		return nil, err
	}

	return key, nil
}

func (e *RIDKeyManager) ImportKey(keyID string, partyID string, data []byte) (comm_rid.RID, error) {
	key, err := e.km.ImportKey(data)
	if err != nil {
		return nil, err
	}

	if err := e.kr.Import(keyID, keyrepository.KeyData{
		PartyID: partyID,
		SKI:     key.SKI(),
	}); err != nil {
		return nil, err
	}

	return key, nil
}

func (e *RIDKeyManager) GetKey(keyID string, partyID string) (comm_rid.RID, error) {
	keys, err := e.kr.GetAll(keyID)
	if err != nil {
		return nil, err
	}

	k, ok := keys[partyID]
	if !ok {
		return nil, errors.New("key not found")
	}

	return e.km.GetKey(string(k.SKI))
}
