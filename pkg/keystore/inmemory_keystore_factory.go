package keystore

import "github.com/mr-shifu/mpc-lib/pkg/common/keystore"

type InmemoryKeystoreFactory struct {}

// NewKeystore creates a new Keystore instance for the given keystore configuration
func (f InmemoryKeystoreFactory) NewKeystore(cfg interface{}) keystore.Keystore {
	return NewInMemoryKeystore()
}