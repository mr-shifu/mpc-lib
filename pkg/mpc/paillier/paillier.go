package paillier

import (
	"errors"

	comm_paillier "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/paillier"
	comm_keyrepository "github.com/mr-shifu/mpc-lib/pkg/common/keyrepository"
	"github.com/mr-shifu/mpc-lib/pkg/keyrepository"
)

type PaillierKeyManager struct {
	km comm_paillier.PaillierKeyManager
	kr comm_keyrepository.KeyRepository
}

type ElgamalKeyData struct {
	PartyID string
	SKI     []byte
}

func NewElgamal(km comm_paillier.PaillierKeyManager, kr comm_keyrepository.KeyRepository) *PaillierKeyManager {
	return &PaillierKeyManager{km, kr}
}

func (e *PaillierKeyManager) GenerateKey(keyID string, partyID string) (comm_paillier.PaillierKey, error) {
	key, err := e.km.GenerateKey()
	if err != nil {
		return nil, err
	}

	ski := key.SKI()

	if err := e.kr.Import(keyID, ElgamalKeyData{partyID, ski}); err != nil {
		return nil, err
	}

	return key, nil
}

func (e *PaillierKeyManager) ImportKey(keyID string, partyID string, data []byte) (comm_paillier.PaillierKey, error) {
	key, err := e.km.ImportKey(data)
	if err != nil {
		return nil, err
	}

	if err := e.kr.Import(keyID, ElgamalKeyData{partyID, key.SKI()}); err != nil {
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

	keyData, ok := k.(keyrepository.Key)
	if !ok {
		return nil, errors.New("key not found")
	}

	ski := keyData.SKI

	return e.km.GetKey(ski)
}
