package commitstore

import (
	"errors"
	"sync"

	"github.com/mr-shifu/mpc-lib/pkg/common/commitstore"
)

var (
	ErrCommitmentAlreadyExists = errors.New("commitment already exists")
	ErrCommitmentNotFound      = errors.New("commitment not found")
)

type InMemoryCommitStore struct {
	lock  sync.RWMutex
	store map[string]*commitstore.Commitment
}

func NewInMemoryCommitstore() *InMemoryCommitStore {
	return &InMemoryCommitStore{
		store: make(map[string]*commitstore.Commitment),
	}
}

func (cs *InMemoryCommitStore) Get(ID string) (*commitstore.Commitment, error) {
	cs.lock.Lock()
	defer cs.lock.Unlock()

	commitment, ok := cs.store[ID]
	if !ok {
		return nil, ErrCommitmentNotFound
	}

	return commitment, nil
}

func (cs *InMemoryCommitStore) Import(ID string, commitment *commitstore.Commitment) error {
	cs.lock.Lock()
	defer cs.lock.Unlock()

	// if _, ok := cs.store[ID]; ok {
	// 	return ErrCommitmentAlreadyExists
	// }

	cs.store[ID] = commitment
	return nil
}

func (cs *InMemoryCommitStore) Delete(ID string) error {
	cs.lock.Lock()
	defer cs.lock.Unlock()

	if _, ok := cs.store[ID]; !ok {
		return ErrCommitmentNotFound
	}

	delete(cs.store, ID)
	return nil
}
