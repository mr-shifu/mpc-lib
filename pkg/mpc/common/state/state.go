package state

type State interface {
	ID() string
	LastRound() int
	SetLastRound(round int)
	Aborted() bool
	SetAborted()
	Completed() bool
	SetCompleted()
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
	Get(ID string) (State, error)
}
