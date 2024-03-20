package keystore

type KeystoreFactory struct {}

// NewKeystore creates a new Keystore instance for the given keystore configuration
func (f *KeystoreFactory) NewKeystore(cfg interface{}) *InMemoryKeystore {
	return NewInMemoryKeystore()
}