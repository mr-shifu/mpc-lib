package keystore

// KeystoreFactory is a factory interface for creating new Keystore instances
type KeystoreFactory interface {
	// Create a new Keystore instance for the given keystore configuration
	NewKeystore(cfg interface{}) Keystore
}