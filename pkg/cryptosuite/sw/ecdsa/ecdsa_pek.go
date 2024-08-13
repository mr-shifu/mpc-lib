package ecdsa

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillier"
	comm_pek "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/paillierencodedkey"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillierencodedkey"
)

// TODO kid is better to be something differnt than ski
// TODO it's better to only use common packages instead of sw so we might be able to change arch of pek
func (key ECDSAKey) EncodeByPaillier(pk paillier.PaillierKey) (comm_pek.PaillierEncodedKey, error) {
	if key.Private() {
		encoded, nonce := pk.Encode(curve.MakeInt(key.priv))
		pek := paillierencodedkey.NewPaillierEncodedkey(nil, encoded, nonce, key.group)
		return pek, nil
	}
	return nil, nil
}
