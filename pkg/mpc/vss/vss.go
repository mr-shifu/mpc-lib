package vss

import (
	"errors"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
	comm_vss "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/vss"
	comm_keyrepository "github.com/mr-shifu/mpc-lib/pkg/common/keyrepository"
	"github.com/mr-shifu/mpc-lib/pkg/keyrepository"
)

type ElgamalKeyManager struct {
	km comm_vss.VssKeyManager
	kr comm_keyrepository.KeyRepository
}

type ElgamalKeyData struct {
	PartyID string
	SKI     []byte
}

func NewElgamal(km comm_vss.VssKeyManager, kr comm_keyrepository.KeyRepository) *ElgamalKeyManager {
	return &ElgamalKeyManager{km, kr}
}

func (e *ElgamalKeyManager) GenerateSecrets(keyID string, partyID string, secret curve.Scalar, degree int) (comm_vss.VssKey, error) {
	key, err := e.km.GenerateSecrets(secret, degree)
	if err != nil {
		return nil, err
	}

	ski := key.SKI()

	if err := e.kr.Import(keyID, ElgamalKeyData{partyID, ski}); err != nil {
		return nil, err
	}

	return key, nil
}

func (e *ElgamalKeyManager) ImportKey(keyID string, partyID string, data []byte) (comm_vss.VssKey, error) {
	key, err := e.km.ImportSecrets(data)
	if err != nil {
		return nil, err
	}

	if err := e.kr.Import(keyID, ElgamalKeyData{partyID, key.SKI()}); err != nil {
		return nil, err
	}

	return key, nil
}

func (e *ElgamalKeyManager) GetKey(keyID string, partyID string) (comm_vss.VssKey, error) {
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

	return e.km.GetSecrets(ski)
}
