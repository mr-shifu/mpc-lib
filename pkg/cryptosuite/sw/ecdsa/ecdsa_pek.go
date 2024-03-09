package ecdsa

import (
	"encoding/hex"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/paillier"
	comm_pek "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/paillierencodedkey"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillierencodedkey"
)

// TODO kid is better to be something differnt than ski
// TODO it's better to only use common packages instead of sw so we might be able to change arch of pek
func (key ECDSAKey) EncodeByPaillier(pk paillier.PaillierKey) (comm_pek.PaillierEncodedKey, error) {
	if key.Private() {
		encoded, nonce := pk.Encode(curve.MakeInt(key.priv))
		kid := hex.EncodeToString(key.SKI())
		pek := paillierencodedkey.NewPaillierEncodedkey(nil, encoded, nonce)
		if err := key.pekmgr.Import(kid, pek); err != nil {
			return nil, err
		}
		return pek, nil
	}
	return nil, nil
}

func (key ECDSAKey) ImportPaillierEncoded(pek comm_pek.PaillierEncodedKey) error {
	kid := hex.EncodeToString(key.SKI())
	if err := key.pekmgr.Import(kid, pek); err != nil {
		return err
	}
	return nil
}

func (key ECDSAKey) GetPaillierEncodedKey() (comm_pek.PaillierEncodedKey, error) {
	kid := hex.EncodeToString(key.SKI())
	return key.pekmgr.Get(kid)
}
