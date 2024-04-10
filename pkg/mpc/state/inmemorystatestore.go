package state

import (
	"errors"
	"sync"
)

type InMemoryStateStore struct {
	lock  sync.RWMutex
	stats map[string]interface{}
}

func NewInMemoryStateStore() *InMemoryStateStore {
	return &InMemoryStateStore{
		stats: make(map[string]interface{}),
	}
}

func (s *InMemoryStateStore) Import(ID string, stat interface{}) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.stats[ID] = stat

	return nil
}

func (s *InMemoryStateStore) Get(ID string) (interface{}, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	stat, ok := s.stats[ID]
	if !ok {
		return nil, errors.New("state not found")
	}

	return stat, nil
}
