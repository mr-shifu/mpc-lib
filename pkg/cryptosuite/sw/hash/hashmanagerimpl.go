package hash

import (
	core_hash "github.com/mr-shifu/mpc-lib/core/hash"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
)

type HashManager struct {
	store keystore.Keystore
}

func NewHashManager(store keystore.Keystore) *HashManager {
	return &HashManager{store: store}
}

func (h *HashManager) NewHasher(keyID string, data ...core_hash.WriterToWithDomain) hash.Hash {
	return New(h.store.WithKeyID(keyID), data...)
}

func (h *HashManager) RestoreHasher(keyID string) (hash.Hash, error) {
	return Restore(h.store.WithKeyID(keyID))
}
