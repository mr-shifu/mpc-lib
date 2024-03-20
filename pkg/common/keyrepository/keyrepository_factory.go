package keyrepository

// KeyRepositoryFactory is a factory for KeyRepository instances
type KeyRepositoryFactory interface {
	// Create a new Keyrepository from a repository configuration
	NewKeyRepository(cfg interface{}) KeyRepository
}