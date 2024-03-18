package mpckey

import (
	"errors"
	"sync"

	comm_mpckey "github.com/mr-shifu/mpc-lib/pkg/mpc/common/mpckey"
)

var (
	ErrKeyAlreadyExists = errors.New("mpckey: key already exists")
	ErrKeyNotFound      = errors.New("mpckey: key not found")
)

type InMemoryMPCKeystore struct {
	lock sync.RWMutex
	keys map[string]comm_mpckey.MPCKey
}

func NewInMemoryMPCKeystore() *InMemoryMPCKeystore {
	return &InMemoryMPCKeystore{
		keys: make(map[string]comm_mpckey.MPCKey),
	}
}

func (ks *InMemoryMPCKeystore) Exists(keyID string) (bool, error) {
	ks.lock.RLock()
	defer ks.lock.RUnlock()

	_, ok := ks.keys[keyID]
	return ok, nil
}

func (ks *InMemoryMPCKeystore) Get(keyID string) (comm_mpckey.MPCKey, error) {
	ks.lock.Lock()
	defer ks.lock.Unlock()

	return ks.keys[keyID], nil
}

func (ks *InMemoryMPCKeystore) Import(key comm_mpckey.MPCKey) error {
	ks.lock.Lock()
	defer ks.lock.Unlock()

	_, ok := ks.keys[key.ID]
	if ok {
		return ErrKeyAlreadyExists
	}

	ks.keys[key.ID] = key
	return nil
}

func (ks *InMemoryMPCKeystore) Update(key comm_mpckey.MPCKey) error {
	ks.lock.Lock()
	defer ks.lock.Unlock()

	_, ok := ks.keys[key.ID]
	if !ok {
		return ErrKeyNotFound
	}

	ks.keys[key.ID] = key
	return nil
}

func (ks *InMemoryMPCKeystore) Delete(keyID string) error {
	ks.lock.Lock()
	defer ks.lock.Unlock()

	_, ok := ks.keys[keyID]
	if !ok {
		return ErrKeyNotFound
	}

	delete(ks.keys, keyID)
	return nil
}
