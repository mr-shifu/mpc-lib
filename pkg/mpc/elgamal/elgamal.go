package elgamal

import (
	"errors"

	comm_elgamal "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/elgamal"
	comm_keyrepository "github.com/mr-shifu/mpc-lib/pkg/common/keyrepository"
	"github.com/mr-shifu/mpc-lib/pkg/keyrepository"
)

type ElgamalKeyManager struct {
	km comm_elgamal.ElgamalKeyManger
	kr comm_keyrepository.KeyRepository
}

type ElgamalKeyData struct {
	PartyID string
	SKI     []byte
}

func NewElgamal(km comm_elgamal.ElgamalKeyManger, kr comm_keyrepository.KeyRepository) *ElgamalKeyManager {
	return &ElgamalKeyManager{km, kr}
}

func (e *ElgamalKeyManager) GenerateKey(keyID string, partyID string) (comm_elgamal.ElgamalKey, error) {
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

func (e *ElgamalKeyManager) ImportKey(keyID string, partyID string, data []byte) (comm_elgamal.ElgamalKey, error) {
	key, err := e.km.ImportKey(data)
	if err != nil {
		return nil, err
	}

	if err := e.kr.Import(keyID, ElgamalKeyData{partyID, key.SKI()}); err != nil {
		return nil, err
	}

	return key, nil
}

func (e *ElgamalKeyManager) GetKey(keyID string, partyID string) (comm_elgamal.ElgamalKey, error) {
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