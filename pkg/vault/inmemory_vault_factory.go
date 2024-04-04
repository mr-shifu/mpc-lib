package vault

import "github.com/mr-shifu/mpc-lib/pkg/common/vault"

type InmemoryVaultFactory struct {}

// NewVault creates a new Vault instance for the given Vault configuration
func (f InmemoryVaultFactory) NewVault(cfg interface{}) vault.Vault {
	return NewInMemoryVault()
}