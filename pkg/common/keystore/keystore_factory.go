package keystore

import (
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/common/vault"
)

// KeystoreFactory is a factory interface for creating new Keystore instances
type KeystoreFactory interface {
	// Create a new Keystore instance for the given keystore configuration
	NewKeystore(v vault.Vault, kr keyopts.KeyOpts, cfg interface{}) Keystore
}
