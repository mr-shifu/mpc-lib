package message

import (
	"errors"
	"sync"

	com_msg "github.com/mr-shifu/mpc-lib/pkg/mpc/common/message"
)

type InMemoryMessageStore struct {
	lock sync.RWMutex

	// Map KeyID -> RoundNumber -> PartyID -> Message
	messages map[string]map[int]map[string]com_msg.Message
}

func NewInMemoryMessageStore() *InMemoryMessageStore {
	return &InMemoryMessageStore{
		messages: make(map[string]map[int]map[string]com_msg.Message),
	}
}

func (s *InMemoryMessageStore) Import(msg com_msg.Message) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	m, ok := msg.(*Message)
	if !ok {
		return errors.New("invalid message type")
	}

	if _, ok := s.messages[m.KeyID()]; !ok {
		s.messages[m.KeyID()] = make(map[int]map[string]com_msg.Message)
	}

	if _, ok := s.messages[m.KeyID()][m.Round()]; !ok {
		s.messages[m.KeyID()][m.Round()] = make(map[string]com_msg.Message)
	}

	s.messages[m.KeyID()][m.Round()][m.PartyID()] = msg

	return nil
}

func (s *InMemoryMessageStore) Get(keyID string, round int, partyID string) (com_msg.Message, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	if _, ok := s.messages[keyID]; !ok {
		return nil, errors.New("message associated with keyID not found")
	}

	if _, ok := s.messages[keyID][round]; !ok {
		return nil, errors.New("message associated with RoundNumber not found")
	}

	msg, ok := s.messages[keyID][round][partyID]
	if !ok {
		return nil, errors.New("message associated with PartyID not found")
	}

	return msg, nil
}

func (s *InMemoryMessageStore) GetAll(keyID string, round int) (map[string]com_msg.Message, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	if _, ok := s.messages[keyID]; !ok {
		return nil, errors.New("message associated with keyID not found")
	}

	msgs, ok := s.messages[keyID][round]
	if !ok {
		return nil, errors.New("message associated with RoundNumber not found")
	}

	return msgs, nil
}
