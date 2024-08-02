package state

type State interface {
	ID() string
	LastRound() int
	SetLastRound(round int)
	Aborted() bool
	SetAborted()
	Completed() bool
	SetCompleted()
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
	SetAborted(ID string) error
	SetCompleted(ID string) error
	SetRefresh(ID string, refresh bool) error
	Get(ID string) (State, error)
}
