package vss

import (
	"errors"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
	comm_vss "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/vss"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyrepository"
)

type VSSKeyManager struct {
	km comm_vss.VssKeyManager
	kr keyrepository.KeyRepository
}

func NewVSS(km comm_vss.VssKeyManager, kr keyrepository.KeyRepository) *VSSKeyManager {
	return &VSSKeyManager{km, kr}
}

func (e *VSSKeyManager) GenerateSecrets(keyID string, partyID string, secret curve.Scalar, degree int) (comm_vss.VssKey, error) {
	key, err := e.km.GenerateSecrets(secret, degree)
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

func (e *VSSKeyManager) ImportKey(keyID string, partyID string, data []byte) (comm_vss.VssKey, error) {
	key, err := e.km.ImportSecrets(data)
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

func (e *VSSKeyManager) GetKey(keyID string, partyID string) (comm_vss.VssKey, error) {
	keys, err := e.kr.GetAll(keyID)
	if err != nil {
		return nil, err
	}

	k, ok := keys[partyID]
	if !ok {
		return nil, errors.New("key not found")
	}

	return e.km.GetSecrets(k.SKI)
}
