package keyopts

import (
	"errors"
	"sync"

	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
)

var (
	ErrInvalidParamsPartyID = errors.New("keyopts: invalid partyID")
	ErrInvalidParamsKeyID   = errors.New("keyopts: invalid keyID")
	ErrKeyNotFound          = errors.New("keyopts: key not found")
)

type Keys map[string]*keyopts.KeyData

type KeyOpts struct {
	lock sync.RWMutex

	// keys is a map of MPC KeyID to a map of PartyID to key metadata{SKI}.
	keys map[string]Keys
}

func NewInMemoryKeyOpts() *KeyOpts {
	return &KeyOpts{
		keys: make(map[string]Keys),
	}
}

func (kr *KeyOpts) Import(data interface{}, opts keyopts.Options) error {
	kr.lock.Lock()
	defer kr.lock.Unlock()

	// get KeyID from Options
	ID, ok := opts.Get("id")
	if !ok {
		return ErrInvalidParamsKeyID
	}
	kid, ok := ID.(string)
	if !ok {
		return ErrInvalidParamsKeyID
	}

	// get PartyID from Options
	partyID, ok := opts.Get("partyid")
	if !ok {
		return ErrInvalidParamsPartyID
	}
	pid, ok := partyID.(string)
	if !ok {
		return ErrInvalidParamsPartyID
	}

	// check if keyID exists otherwise create a new entry
	if _, ok := kr.keys[kid]; !ok {
		kr.keys[kid] = make(map[string]*keyopts.KeyData)
	}

	// import key data
	d, ok := data.(string)
	if !ok {
		return errors.New("keyopts: invalid data")
	}
	kd := &keyopts.KeyData{
		SKI:     d,
		PartyID: pid,
	}
	kr.keys[kid][pid] = kd

	return nil
}

func (kr *KeyOpts) Get(opts keyopts.Options) (*keyopts.KeyData, error) {
	kr.lock.RLock()
	defer kr.lock.RUnlock()

	// get KeyID from Options
	ID, ok := opts.Get("id")
	if !ok {
		return nil, ErrInvalidParamsKeyID
	}
	kid, ok := ID.(string)
	if !ok {
		return nil, ErrInvalidParamsKeyID
	}

	// get PartyID from Options
	partyID, ok := opts.Get("partyid")
	if !ok {
		return nil, ErrInvalidParamsPartyID
	}
	pid, ok := partyID.(string)
	if !ok {
		return nil, ErrInvalidParamsPartyID
	}

	ks, ok := kr.keys[kid]
	if !ok {
		return nil, ErrKeyNotFound
	}

	k, ok := ks[pid]
	if !ok {
		return nil, ErrKeyNotFound
	}

	return k, nil
}

func (kr *KeyOpts) GetAll(opts keyopts.Options) (map[string]*keyopts.KeyData, error) {
	kr.lock.RLock()
	defer kr.lock.RUnlock()

	ID, ok := opts.Get("id")
	if !ok {
		return nil, ErrInvalidParamsKeyID
	}
	kid, ok := ID.(string)
	if !ok {
		return nil, ErrInvalidParamsKeyID
	}

	ks, ok := kr.keys[kid]
	if !ok {
		return nil, ErrKeyNotFound
	}

	result := make(map[string]*keyopts.KeyData)
	for partyID, key := range ks {
		result[partyID] = key
	}
	return result, nil
}

func (kr *KeyOpts) Delete(opts keyopts.Options) error {
	kr.lock.Lock()
	defer kr.lock.Unlock()

	// get KeyID from Options
	ID, ok := opts.Get("id")
	if !ok {
		return ErrInvalidParamsKeyID
	}
	kid, ok := ID.(string)
	if !ok {
		return ErrInvalidParamsKeyID
	}

	// get PartyID from Options
	partyID, ok := opts.Get("partyid")
	if !ok {
		return ErrInvalidParamsPartyID
	}
	pid, ok := partyID.(string)
	if !ok {
		return ErrInvalidParamsPartyID
	}

	ks, ok := kr.keys[kid]
	if !ok {
		return ErrKeyNotFound
	}

	delete(ks, pid)

	return nil
}

func (kr *KeyOpts) DeleteAll(opts keyopts.Options) error {
	kr.lock.Lock()
	defer kr.lock.Unlock()

	// get KeyID from Options
	ID, ok := opts.Get("id")
	if !ok {
		return ErrInvalidParamsKeyID
	}
	kid, ok := ID.(string)
	if !ok {
		return ErrInvalidParamsKeyID
	}

	delete(kr.keys, kid)

	return nil
}
