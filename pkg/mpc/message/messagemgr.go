package message

import com_msg "github.com/mr-shifu/mpc-lib/pkg/mpc/common/message"

type MessageManager struct {
	store com_msg.MessageStore
}

func NewMessageManager(store com_msg.MessageStore) *MessageManager {
	return &MessageManager{
		store: store,
	}
}

func (m *MessageManager) NewMessage(id string, round int, partyID string, verified bool) com_msg.Message {
	return &Message{
		id:       id,
		round:    round,
		partyID:  partyID,
		verified: verified,
	}
}

func (m *MessageManager) Import(msg com_msg.Message) error {
	return m.store.Import(msg)
}

func (m *MessageManager) Get(keyID string, round int, partyID string) (com_msg.Message, error) {
	return m.store.Get(keyID, round, partyID)
}

func (m *MessageManager) GetAll(keyID string, round int) (map[string]com_msg.Message, error) {
	return m.store.GetAll(keyID, round)
}

func (m *MessageManager) HasAll(keyID string, round int, partyIDs []string) (bool, error) {
	msgs, err := m.store.GetAll(keyID, round)
	if err != nil {
		return false, err
	}

	for _, partyID := range partyIDs {
		if _, ok := msgs[partyID]; !ok {
			return false, nil
		}
	}

	return true, nil
}
