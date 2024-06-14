package state

import (
	"errors"
	"sync"

	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/state"
)

type InMemoryStateStore struct {
	lock  sync.RWMutex
	stats map[string]*State
}

var _ state.MPCStateStore = (*InMemoryStateStore)(nil)

func NewInMemoryStateStore() *InMemoryStateStore {
	return &InMemoryStateStore{
		stats: make(map[string]*State),
	}
}

func (s *InMemoryStateStore) Import(ID string, stat state.State) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.stats[ID] = &State{
		id:        stat.ID(),
		lastRound: stat.LastRound(),
		aborted:   stat.Aborted(),
		completed: stat.Completed(),
	}

	return nil
}

func (s *InMemoryStateStore) Get(ID string) (state.State, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	stat, ok := s.stats[ID]
	if !ok {
		return nil, errors.New("state not found")
	}

	return stat, nil
}
