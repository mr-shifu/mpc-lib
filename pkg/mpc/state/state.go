package state

type State struct {
	id        string
	lastRound int
	aborted   bool
	completed bool
	refresh   bool
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

func (s *State) SetLastRound(round int) {
	s.lastRound = round
}

func (s *State) Aborted() bool {
	return s.aborted
}

func (s *State) SetAborted() {
	s.aborted = true
}

func (s *State) Completed() bool {
	return s.completed
}

func (s *State) SetCompleted() {
	s.completed = true
}

func (s *State) Refresh() bool {
	return s.refresh
}

func (s *State) SetRefresh(refresh bool) {
	s.refresh = refresh
}