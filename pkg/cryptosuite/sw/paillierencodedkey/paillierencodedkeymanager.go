package paillierencodedkey

import (
	pek "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/paillierencodedkey"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
)

type PaillierEncodedKeyManager struct {
	store keystore.Keystore
}

func NewPaillierEncodedKeyManager(store keystore.Keystore) *PaillierEncodedKeyManager {
	return &PaillierEncodedKeyManager{
		store: store,
	}
}

func (k *PaillierEncodedKeyManager) Get(keyID string) (pek.PaillierEncodedKey, error) {
	b, err := k.store.Get(keyID)
	if err != nil {
		return nil, err
	}
	return fromBytes(b)
}

func (k *PaillierEncodedKeyManager) Import(keyID string, key pek.PaillierEncodedKey) (pek.PaillierEncodedKey, error) {
	b, err := key.Bytes()
	if err != nil {
		return nil, err
	}
	err = k.store.Import(keyID, b)
	if err != nil {
		return nil, err
	}
	return key, nil
}