package keyrepository

import (
	"errors"
	"sync"
)

type Key struct {
	SKI     []byte
	PartyID string
}

type Keys map[string]Key 

type KeyRepository struct {
	lock sync.RWMutex

	// keys is a map of MPC KeyID to a map of PartyID to key metadata{SKI}.
	keys map[string]Keys
}

func NewKeyRepository() *KeyRepository {
	return &KeyRepository{
		keys: make(map[string]Keys),
	}
}

func (kr *KeyRepository) Import(ID string, key Key) error {
	kr.lock.Lock()
	defer kr.lock.Unlock()

	// verify if the key is valid
	if key.PartyID == "" {
		return errors.New("invalud partyID")
	}

	if _, ok := kr.keys[ID]; !ok {
		kr.keys[ID] = make(map[string]Key)
	}

	kr.keys[ID][key.PartyID] = key
	return nil
}

func (kr *KeyRepository) GetAll(ID string) ([]Key, error) {
	kr.lock.RLock()
	defer kr.lock.RUnlock()

	ks, ok := kr.keys[ID]
	if !ok {
		return nil, errors.New("key not found")
	}

	var keys []Key
	for _, key := range ks {
		keys = append(keys, key)
	}
	return keys, nil
}

func (kr *KeyRepository) DeleteAll(ID string) error {
	kr.lock.Lock()
	defer kr.lock.Unlock()

	_, ok := kr.keys[ID]
	if !ok {
		return errors.New("key not found")
	}

	delete(kr.keys, ID)
	return nil
}