package message

type Message struct {
	keyID     string
	round     int
	partyID   string
	verified  bool
}

func (m *Message) KeyID() string {
	return m.keyID
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
