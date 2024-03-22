package keyrepository

import "github.com/mr-shifu/mpc-lib/pkg/common/keyrepository"

type InMemoryKeyRepositoryFactory struct {}

// NewKeyRepository creates a new KeyRepository instance for the given repository configuration
func (f *InMemoryKeyRepositoryFactory) NewKeyRepository(cfg interface{}) keyrepository.KeyRepository {
	return NewKeyRepository()
}