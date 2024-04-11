package message

type Message interface {
	KeyID() string
	Round() int
	PartyID() string
	Verified() bool
}

type MessageStore interface {
	Import(msg Message) error
	Get(keyID string, round int, partyID string) (Message, error)
	GetAll(keyID string, round int) (map[string]Message, error)
}

type MessageManager interface {
	NewMessage(keyID string, round int, partyID string, verified bool) Message
	Import(msg Message) error
	Get(keyID string, round int, partyID string) (Message, error)
	GetAll(keyID string, round int) (map[string]Message, error)
	HasAll(keyID string, round int, partyIDs []string) (bool, error)
}
