package hash

import (
	core_hash "github.com/mr-shifu/mpc-lib/core/hash"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
)

type HashManagerImpl struct {
	store keystore.Keystore
}

var _ HashManager = (*HashManagerImpl)(nil)

func NewHashManager(store keystore.Keystore) *HashManagerImpl {
	return &HashManagerImpl{store: store}
}

func (h *HashManagerImpl) NewHasher(keyID string, opts keyopts.Options, data ...core_hash.WriterToWithDomain) Hash {
	return New(h.store.KeyAccessor(keyID, opts), data...)
}

func (h *HashManagerImpl) RestoreHasher(keyID string, opts keyopts.Options) (Hash, error) {
	return Restore(h.store.KeyAccessor(keyID, opts))
}
