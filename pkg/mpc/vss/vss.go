package vss

import (
	"encoding/hex"
	"errors"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/party"
	comm_ecdsa "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/ecdsa"
	comm_vss "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/vss"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyrepository"
	sw_ecdsa "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ecdsa"
)

type VSSKeyManager struct {
	km comm_vss.VssKeyManager
	kr keyrepository.KeyRepository

	ec_km comm_ecdsa.ECDSAKeyManager
	ec_kr keyrepository.KeyRepository
}

func NewVSS(
	km comm_vss.VssKeyManager,
	kr keyrepository.KeyRepository,
	ec_km comm_ecdsa.ECDSAKeyManager,
	ec_kr keyrepository.KeyRepository) *VSSKeyManager {
	return &VSSKeyManager{km, kr, ec_km, ec_kr}
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

func (mgr *VSSKeyManager) GenerateVSSShare(keyID string, vss_partyID party.ID, ec_partyID party.ID, group curve.Curve) error {
	vss, err := mgr.GetKey(keyID, string(vss_partyID))
	if err != nil {
		return err
	}
	share, err := vss.Evaluate(ec_partyID.Scalar(group))
	if err != nil {
		return err
	}
	sharePublic := share.ActOnBase()

	shareKey := sw_ecdsa.NewECDSAKey(share, sharePublic, group)
	if _, err := mgr.ec_km.ImportKey(shareKey); err != nil {
		return err
	}

	shareID := hex.EncodeToString(vss.SKI())

	if err := mgr.ec_kr.Import(shareID, keyrepository.KeyData{
		PartyID: string(ec_partyID),
		SKI:     shareKey.SKI(),
	}); err != nil {
		return err
	}

	return nil
}

func (mgr *VSSKeyManager) ImportShare(keyID string, vss_partyID party.ID, ec_partyID party.ID, share comm_ecdsa.ECDSAKey) error {
	vss, err := mgr.GetKey(keyID, string(vss_partyID))
	if err != nil {
		return err
	}

	if _, err := mgr.ec_km.ImportKey(share); err != nil {
		return err
	}

	shareID := hex.EncodeToString(vss.SKI())
	if err := mgr.ec_kr.Import(shareID, keyrepository.KeyData{
		PartyID: string(ec_partyID),
		SKI:     share.SKI(),
	}); err != nil {
		return err
	}

	return nil
}

func (mgr *VSSKeyManager) GetShare(keyID string, vss_partyID party.ID, ec_partyID party.ID) (comm_ecdsa.ECDSAKey, error) {
	vss, err := mgr.GetKey(keyID, string(vss_partyID))
	if err != nil {
		return nil, err
	}

	shareId := hex.EncodeToString(vss.SKI())

	keys, err := mgr.ec_kr.GetAll(shareId)
	if err != nil {
		return nil, err
	}
	kid, ok := keys[string(ec_partyID)]
	if !ok {
		return nil, errors.New("key not found")
	}

	return mgr.ec_km.GetKey(kid.SKI)
}