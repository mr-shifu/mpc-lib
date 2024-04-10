package state

type State struct {
	id        string
	lastRound int
	aborted   bool
	completed bool
}

func NewState(id string) *State {
	return &State{
		id: id,
	}
}

func (s *State) ID() string {
	return s.id
}

func (s *State) LastRound() int {
	return s.lastRound
}

func (s *State) Aborted() bool {
	return s.aborted
}

func (s *State) Completed() bool {
	return s.completed
}