package ecdsa

import (
	"errors"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/math/polynomial"
	"github.com/mr-shifu/mpc-lib/core/party"
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

	if e.vsskr != nil {
		if err := e.vsskr.Import(keyID, keyrepository.KeyData{
			PartyID: partyID,
			SKI:     ski,
		}); err != nil {
			return nil, err
		}
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

	if e.vsskr != nil {
		if err := e.vsskr.Import(keyID, keyrepository.KeyData{
			PartyID: partyID,
			SKI:     key.SKI(),
		}); err != nil {
			return err
		}
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
		return nil, errors.New("ecdsa: key not found")
	}

	return e.km.GetKey(k.SKI)
}

func (e *ECDSAKeyManager) GetAllKeys(keyID string) (map[string]comm_ecdsa.ECDSAKey, error) {
	keys, err := e.kr.GetAll(keyID)
	if err != nil {
		return nil, err
	}

	ret := make(map[string]comm_ecdsa.ECDSAKey)
	for _, k := range keys {
		key, err := e.km.GetKey(k.SKI)
		if err != nil {
			return nil, err
		}

		ret[k.PartyID] = key
	}

	return ret, nil
}

func (e *ECDSAKeyManager) GetVSSKey(keyID string, partyID string) (comm_vss.VssKey, error) {
	keys, err := e.kr.GetAll(keyID)
	if err != nil {
		return nil, err
	}

	k, ok := keys[partyID]
	if !ok {
		return nil, errors.New("ecdsa: key not found")
	}

	ecKey, err := e.km.GetKey(k.SKI)
	if err != nil {
		return nil, err
	}

	return ecKey.VSS()
}

func (e *ECDSAKeyManager) GenerateMPCKeyFromShares(keyID string, selfID party.ID, group curve.Curve) error {
	ecKeys, err := e.GetAllKeys(keyID)
	if err != nil {
		return err
	}

	// Calculate MPC public Key
	mpcPublicKey := group.NewPoint()
	for _, key := range ecKeys {
		vssKey, err := key.VSS()
		if err != nil {
			return err
		}
		exp, err := vssKey.ExponentsRaw()
		if err != nil {
			return err
		}
		pub := exp.Constant()
		mpcPublicKey = mpcPublicKey.Add(pub)
	}

	// Import MPC public Key
	k := e.km.NewKey(nil, mpcPublicKey, group)
	if err := e.ImportKey(keyID, "ROOT", k); err != nil {
		return err
	}

	// Calculate MPC VSS Exponents of all VSS keys
	var allExponents []*polynomial.Exponent
	for _, key := range ecKeys {
		vssKey, err := key.VSS()
		if err != nil {
			return err
		}
		exp, err := vssKey.ExponentsRaw()
		if err != nil {
			return err
		}
		allExponents = append(allExponents, exp)
	}
	mpcExponent, err := polynomial.Sum(allExponents)
	if err != nil {
		return err
	}
	mpcExponentBytes, err := mpcExponent.MarshalBinary()
	if err != nil {
		return err
	}
	_, err = e.vssmgr.ImportSecrets(mpcExponentBytes)
	if err != nil {
		return err
	}

	return nil
}

