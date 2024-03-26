package pedersen

import (
	"errors"

	comm_pedersen "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/pedersen"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyrepository"
)

type PedersenKeyManager struct {
	km comm_pedersen.PedersenKeyManager
	kr keyrepository.KeyRepository
}

func NewPedersenKeyManager(km comm_pedersen.PedersenKeyManager, kr keyrepository.KeyRepository) *PedersenKeyManager {
	return &PedersenKeyManager{km, kr}
}

func (e *PedersenKeyManager) ImportKey(keyID string, partyID string, raw interface{}) (comm_pedersen.PedersenKey, error) {
	key, err := e.km.ImportKey(raw)
	if err != nil {
		return nil, err
	}

	if err := e.kr.Import(keyID, keyrepository.KeyData{
		PartyID: partyID,
		SKI:     key.SKI(),
	}); err != nil {
		return nil, err
	}

	return  key, nil
}

func (e *PedersenKeyManager) GetKey(keyID string, partyID string) (comm_pedersen.PedersenKey, error) {
	keys, err := e.kr.GetAll(keyID)
	if err != nil {
		return nil, err
	}

	k, ok := keys[partyID]
	if !ok {
		return nil, errors.New("key not found")
	}

	return e.km.GetKey(k.SKI)
}
