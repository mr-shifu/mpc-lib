package state

type State interface {
	ID() string
	LastRound() int
	Aborted() bool
	Completed() bool
}

type MPCStateStore interface {
	Import(ID string, stat interface{}) error
	Get(ID string) (interface{}, error)
}

type MPCStateManager interface {
	NewState(ID string) error
	Import(stat State) error
	SetLastRound(ID string, round int) error
	SetAborted(ID string) error
	SetCompleted(ID string) error
	Get(ID string) (State, error)
}
