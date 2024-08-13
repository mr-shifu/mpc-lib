package state

type State interface {
	ID() string
	LastRound() int
	SetLastRound(round int)
	Aborted() bool
	SetAborted(aborted bool)
	Completed() bool
	SetCompleted(completed bool)
	Refresh() bool
	SetRefresh(refresh bool)
}

type MPCStateStore interface {
	Import(ID string, stat State) error
	Get(ID string) (State, error)
}

type MPCStateManager interface {
	NewState(ID string) error
	Import(stat State) error
	SetLastRound(ID string, round int) error
	SetAborted(ID string, aborted bool) error
	SetCompleted(ID string, completed bool) error
	SetRefresh(ID string, refresh bool) error
	Get(ID string) (State, error)
}
