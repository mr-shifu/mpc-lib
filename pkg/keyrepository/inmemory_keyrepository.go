package keyrepository

import (
	"errors"
	"sync"

	"github.com/mr-shifu/mpc-lib/pkg/common/keyrepository"
)

var (
	ErrInvalidParamsPartyID = errors.New("keyrepository: invalud partyID")
	ErrKeyNotFound          = errors.New("keyrepository: key not found")
)

type Keys map[string]keyrepository.KeyData

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

func (kr *KeyRepository) Import(ID string, key keyrepository.KeyData) error {
	kr.lock.Lock()
	defer kr.lock.Unlock()

	// verify if the key is valid
	if key.PartyID == "" {
		return ErrInvalidParamsPartyID
	}

	if _, ok := kr.keys[ID]; !ok {
		kr.keys[ID] = make(map[string]keyrepository.KeyData)
	}

	kr.keys[ID][key.PartyID] = key
	return nil
}

func (kr *KeyRepository) GetAll(ID string) (map[string]keyrepository.KeyData, error) {
	kr.lock.RLock()
	defer kr.lock.RUnlock()

	ks, ok := kr.keys[ID]
	if !ok {
		return nil, ErrKeyNotFound
	}

	result := make(map[string]keyrepository.KeyData)
	for partyID, key := range ks {
		result[partyID] = key
	}
	return result, nil
}

func (kr *KeyRepository) DeleteAll(ID string) error {
	kr.lock.Lock()
	defer kr.lock.Unlock()

	_, ok := kr.keys[ID]
	if !ok {
		return ErrKeyNotFound
	}

	delete(kr.keys, ID)
	return nil
}
