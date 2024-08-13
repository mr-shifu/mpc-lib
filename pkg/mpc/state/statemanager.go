package state

import (
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

func (m *MPCStateManager) Import(state com_state.State) error {
	return m.store.Import(state.ID(), state)
}

func (mgr *MPCStateManager) SetLastRound(ID string, round int) error {
	state, err := mgr.store.Get(ID)
	if err != nil {
		return err
	}

	state.SetLastRound(round)

	return mgr.Import(state)
}

func (mgr *MPCStateManager) SetAborted(ID string, aborted bool) error {
	state, err := mgr.store.Get(ID)
	if err != nil {
		return err
	}

	state.SetAborted(aborted)

	return mgr.Import(state)
}

func (mgr *MPCStateManager) SetCompleted(ID string, completed bool) error {
	state, err := mgr.store.Get(ID)
	if err != nil {
		return err
	}

	state.SetCompleted(completed)

	return mgr.Import(state)
}

func (mgr *MPCStateManager) SetRefresh(ID string, refresh bool) error {
	state, err := mgr.store.Get(ID)
	if err != nil {
		return err
	}

	state.SetRefresh(refresh)

	return mgr.Import(state)
}

func (m *MPCStateManager) Get(ID string) (com_state.State, error) {
	return m.store.Get(ID)
}
