package vault

// VaultFactory is a factory interface for creating new Keystore instances
type VaultFactory interface {
	// Create a new Keystore instance for the given keystore configuration
	NewVault(cfg interface{}) Vault
}