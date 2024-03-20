package keyrepository

type KeyRepositoryFactory struct {}

// NewKeyRepository creates a new KeyRepository instance for the given repository configuration
func (f *KeyRepositoryFactory) NewKeyRepository(cfg interface{}) *KeyRepository {
	return NewKeyRepository()
}