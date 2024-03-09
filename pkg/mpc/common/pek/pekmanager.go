package pek

import (
	comm_pek "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/paillierencodedkey"
)

type PaillierEncodedKeyManager interface {
	GetKey(keyID string, partyID string) (comm_pek.PaillierEncodedKey, error)
	ImportKey(keyID string, partyID string, k comm_pek.PaillierEncodedKey) (comm_pek.PaillierEncodedKey, error)
}
