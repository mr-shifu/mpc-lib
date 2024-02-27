package hash

import "github.com/mr-shifu/mpc-lib/pkg/common/keystore"

type HashManager struct {
	store keystore.Keystore
}

func NewHashManager(store keystore.Keystore) *HashManager {
	return &HashManager{store: store}
}

func (h *HashManager) NewHasher(keyID string) *Hash {
	return New(h.store.WithKeyID(keyID))
}

func (h *HashManager) RestoreHasher(keyID string) (*Hash, error) {
	return Restore(h.store.WithKeyID(keyID))
}