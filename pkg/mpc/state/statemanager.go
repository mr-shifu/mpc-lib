package state

import (
	"errors"

	com_state "github.com/mr-shifu/mpc-lib/pkg/mpc/common/state"
)

type MPCStateManager struct {
	store com_state.MPCStateStore
}

func NewMPCStateManager(store com_state.MPCStateStore) com_state.MPCStateManager {
	return &MPCStateManager{
		store: store,
	}
}

func (mgr *MPCStateManager) NewState(ID string) error {
	s := NewState(ID)
	return mgr.Import(s)
}

func (m *MPCStateManager) Import(stat com_state.State) error {
	s, ok := stat.(*State)
	if !ok {
		return errors.New("invalid state type")
	}
	return m.store.Import(stat.ID(), s)
}

func (mgr *MPCStateManager) SetLastRound(ID string, round int) error {
	state, err := mgr.store.Get(ID)
	if err != nil {
		return err
	}

	s, ok := state.(*State)
	if !ok {
		return errors.New("invalid state type")
	}

	s.lastRound = round

	return mgr.Import(s)
}

func (mgr *MPCStateManager) SetAborted(ID string) error {
	state, err := mgr.store.Get(ID)
	if err != nil {
		return err
	}

	s, ok := state.(*State)
	if !ok {
		return errors.New("invalid state type")
	}

	s.aborted = true

	return mgr.Import(s)
}

func (mgr *MPCStateManager) SetCompleted(ID string) error {
	state, err := mgr.store.Get(ID)
	if err != nil {
		return err
	}

	s, ok := state.(*State)
	if !ok {
		return errors.New("invalid state type")
	}

	s.completed = true

	return mgr.Import(s)
}

func (m *MPCStateManager) Get(ID string) (com_state.State, error) {
	state, err := m.store.Get(ID)
	if err != nil {
		return nil, err
	}

	s, ok := state.(*State)
	if !ok {
		return nil, errors.New("invalid state type")
	}

	return s, nil
}
