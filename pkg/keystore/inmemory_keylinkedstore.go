package keystore

type InMemoryKeyLinkedStore struct {
	keyID string
	store *InMemoryKeystore
}

func NewInMemoryKeyLinkedStore(keyID string, store *InMemoryKeystore) *InMemoryKeyLinkedStore {
	return &InMemoryKeyLinkedStore{keyID: keyID, store: store}
}

func (kls *InMemoryKeyLinkedStore) Import(key []byte) error {
	return kls.store.Import(kls.keyID, key)
}

func (kls *InMemoryKeyLinkedStore) Get() ([]byte, error) {
	return kls.store.Get(kls.keyID)
}

func (kls *InMemoryKeyLinkedStore) Delete() error {
	return kls.store.Delete(kls.keyID)
}
