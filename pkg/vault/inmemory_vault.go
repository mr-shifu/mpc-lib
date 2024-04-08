package vault

import (
	"errors"
	"sync"
)

var (
	ErrKeyNotFound = errors.New("vault: key not found")
)

type InMemoryVault struct {
	lock sync.RWMutex
	keys map[string][]byte
}

func NewInMemoryVault() *InMemoryVault {
	return &InMemoryVault{
		keys: make(map[string][]byte),
	}
}

func (store *InMemoryVault) Import(keyID string, key []byte) error {
	store.lock.Lock()
	defer store.lock.Unlock()

	store.keys[keyID] = key
	return nil
}

func (store *InMemoryVault) Get(keyID string) ([]byte, error) {
	store.lock.RLock()
	defer store.lock.RUnlock()

	key, ok := store.keys[keyID]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return key, nil
}

func (store *InMemoryVault) Delete(keyID string) error {
	store.lock.Lock()
	defer store.lock.Unlock()

	delete(store.keys, keyID)
	return nil
}
