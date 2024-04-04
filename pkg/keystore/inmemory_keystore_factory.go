package keystore

import (
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/common/vault"
)

type InmemoryKeystoreFactory struct {}

// NewKeystore creates a new Keystore instance for the given keystore configuration
func (f InmemoryKeystoreFactory) NewKeystore(v vault.Vault, kr keyopts.KeyOpts, cfg interface{}) keystore.Keystore {
	return NewInMemoryKeystore(v, kr)
}