package config

import (
	"errors"
	"sync"
)

type InMemoryConfigStore struct {
	lock    sync.RWMutex
	configs map[string]interface{}
}

func (s *InMemoryConfigStore) Import(ID string, config interface{}) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.configs[ID] = config

	return nil
}

func (s *InMemoryConfigStore) Get(ID string) (interface{}, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	config, ok := s.configs[ID]
	if !ok {
		return nil, errors.New("config not found")
	}

	return config, nil
}
