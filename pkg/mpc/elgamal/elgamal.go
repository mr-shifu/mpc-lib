package elgamal

import (
	"errors"

	comm_elgamal "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/elgamal"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyrepository"
	comm_keyrepository "github.com/mr-shifu/mpc-lib/pkg/common/keyrepository"
)

var (
	ErrKeyNotFound = errors.New("elgamal: key not found")
)

type ElgamalKeyManager struct {
	km comm_elgamal.ElgamalKeyManager
	kr comm_keyrepository.KeyRepository
}

func NewElgamal(km comm_elgamal.ElgamalKeyManager, kr comm_keyrepository.KeyRepository) *ElgamalKeyManager {
	return &ElgamalKeyManager{km, kr}
}

func (e *ElgamalKeyManager) GenerateKey(keyID string, partyID string) (comm_elgamal.ElgamalKey, error) {
	key, err := e.km.GenerateKey()
	if err != nil {
		return nil, err
	}

	ski := key.SKI()

	if err := e.kr.Import(keyID, keyrepository.KeyData{
		PartyID: partyID,
		SKI:     ski,
	}); err != nil {
		return nil, err
	}

	return key, nil
}

func (e *ElgamalKeyManager) ImportKey(keyID string, partyID string, raw interface{}) (comm_elgamal.ElgamalKey, error) {
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

func (e *ElgamalKeyManager) GetKey(keyID string, partyID string) (comm_elgamal.ElgamalKey, error) {
	keys, err := e.kr.GetAll(keyID)
	if err != nil {
		return nil, err
	}

	k, ok := keys[partyID]
	if !ok {
		return nil, ErrKeyNotFound
	}

	return e.km.GetKey(k.SKI)
}
