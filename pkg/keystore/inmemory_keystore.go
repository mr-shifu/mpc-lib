package keystore

import (
	"errors"
	"sync"

	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
)

var (
	ErrKeyNotFound = errors.New("key not found")
)

type InMemoryKeystore struct {
	lock sync.RWMutex
	keys map[string][]byte
}

func NewInMemoryKeystore() *InMemoryKeystore {
	return &InMemoryKeystore{
		keys: make(map[string][]byte),
	}
}

func (store *InMemoryKeystore) Import(keyID string, key []byte) error {
	store.lock.Lock()
	defer store.lock.Unlock()

	store.keys[keyID] = key
	return nil
}

func (store *InMemoryKeystore) Get(keyID string) ([]byte, error) {
	store.lock.RLock()
	defer store.lock.RUnlock()

	key, ok := store.keys[keyID]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return key, nil
}

func (store *InMemoryKeystore) Delete(keyID string) error {
	store.lock.Lock()
	defer store.lock.Unlock()

	delete(store.keys, keyID)
	return nil
}

func (store *InMemoryKeystore) WithKeyID(keyID string) keystore.KeyLinkedStore {
	return NewInMemoryKeyLinkedStore(keyID, store)
}
