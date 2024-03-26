package paillier

import (
	"errors"

	comm_paillier "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/paillier"
	comm_pedersen "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/pedersen"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyrepository"
)

type PaillierKeyManager struct {
	km comm_paillier.PaillierKeyManager
	kr keyrepository.KeyRepository
}

func NewPaillierKeyManager(km comm_paillier.PaillierKeyManager, kr keyrepository.KeyRepository) *PaillierKeyManager {
	return &PaillierKeyManager{km, kr}
}

func (e *PaillierKeyManager) GenerateKey(keyID string, partyID string) (comm_paillier.PaillierKey, error) {
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

func (e *PaillierKeyManager) ImportKey(keyID string, partyID string, raw interface{}) (comm_paillier.PaillierKey, error) {
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

	return key, nil
}

func (e *PaillierKeyManager) GetKey(keyID string, partyID string) (comm_paillier.PaillierKey, error) {
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

func (e *PaillierKeyManager) DerivePedersenKey(keyID string, partyID string) (comm_pedersen.PedersenKey, error) {
	keys, err := e.kr.GetAll(keyID)
	if err != nil {
		return nil, err
	}

	k, ok := keys[partyID]
	if !ok {
		return nil, errors.New("key not found")
	}

	key, err := e.km.GetKey(k.SKI)
	if err != nil {
		return nil, err
	}

	return key.DerivePedersenKey()
}
