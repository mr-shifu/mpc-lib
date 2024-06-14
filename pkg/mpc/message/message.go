package message

type Message struct {
	id     string
	round     int
	partyID   string
	verified  bool
}

func NewMessage(id string, round int, partyID string, verified bool) *Message {
	return &Message{
		id:     id,
		round:     round,
		partyID:   partyID,
		verified:  verified,
	}
}

func (m *Message) ID() string {
	return m.id
}

func (m *Message) Round() int {
	return m.round
}

func (m *Message) PartyID() string {
	return m.partyID
}

func (m *Message) Verified() bool {
	return m.verified
}
