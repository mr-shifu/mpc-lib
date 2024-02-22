package pedersen

import (
	"errors"

	comm_pedersen "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/pedersen"
	comm_keyrepository "github.com/mr-shifu/mpc-lib/pkg/common/keyrepository"
	"github.com/mr-shifu/mpc-lib/pkg/keyrepository"
)

type PedersenKeyManager struct {
	km comm_pedersen.PedersenKeyManager
	kr comm_keyrepository.KeyRepository
}

type ElgamalKeyData struct {
	PartyID string
	SKI     []byte
}

func NewElgamal(km comm_pedersen.PedersenKeyManager, kr comm_keyrepository.KeyRepository) *PedersenKeyManager {
	return &PedersenKeyManager{km, kr}
}

func (e *PedersenKeyManager) ImportKey(keyID string, partyID string, data []byte) (comm_pedersen.PedersenKey, error) {
	key, err := e.km.ImportKey(data)
	if err != nil {
		return nil, err
	}

	if err := e.kr.Import(keyID, ElgamalKeyData{partyID, key.SKI()}); err != nil {
		return nil, err
	}

	return key, nil
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

	keyData, ok := k.(keyrepository.Key)
	if !ok {
		return nil, errors.New("key not found")
	}

	ski := keyData.SKI

	return e.km.GetKey(ski)
}
