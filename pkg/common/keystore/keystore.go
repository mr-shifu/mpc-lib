package keystore

type Keystore interface {
	Import(keyID string, key []byte) error
	Get(keyID string) ([]byte, error)
	Delete(keyID string) error
	WithKeyID(keyID string) KeyLinkedStore
}

type KeyLinkedStore interface {
	Import(key []byte) error
	Get() ([]byte, error)
	Delete() error
}
