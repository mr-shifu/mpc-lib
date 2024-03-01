package ecdsa

import (
	"errors"

	comm_ecdsa "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/ecdsa"
	comm_vss "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/vss"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyrepository"
)

type ECDSAKeyManager struct {
	km     comm_ecdsa.ECDSAKeyManager
	kr     keyrepository.KeyRepository
	vssmgr comm_vss.VssKeyManager
	vsskr  keyrepository.KeyRepository
}

func NewECDSA(km comm_ecdsa.ECDSAKeyManager, kr keyrepository.KeyRepository, vssmgr comm_vss.VssKeyManager, vsskr keyrepository.KeyRepository) *ECDSAKeyManager {
	return &ECDSAKeyManager{km, kr, vssmgr, vsskr}
}

func (e *ECDSAKeyManager) GenerateKey(keyID string, partyID string) (comm_ecdsa.ECDSAKey, error) {
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

	if err := e.vsskr.Import(keyID, keyrepository.KeyData{
		PartyID: partyID,
		SKI:     ski,
	}); err != nil {
		return nil, err
	}

	return key, nil
}

func (e *ECDSAKeyManager) ImportKey(keyID string, partyID string, key comm_ecdsa.ECDSAKey) error {
	if _, err := e.km.ImportKey(key); err != nil {
		return err
	}

	if err := e.kr.Import(keyID, keyrepository.KeyData{
		PartyID: partyID,
		SKI:     key.SKI(),
	}); err != nil {
		return err
	}

	if err := e.vsskr.Import(keyID, keyrepository.KeyData{
		PartyID: partyID,
		SKI:     key.SKI(),
	}); err != nil {
		return err
	}

	return nil
}

func (e *ECDSAKeyManager) GetKey(keyID string, partyID string) (comm_ecdsa.ECDSAKey, error) {
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
