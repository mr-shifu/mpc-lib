package keygen

import (
	"encoding/json"
	"errors"

	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/pkg/math/curve"
	"github.com/mr-shifu/mpc-lib/pkg/party"
	"github.com/mr-shifu/mpc-lib/pkg/pool"
	sch "github.com/mr-shifu/mpc-lib/pkg/zk/sch"
	"github.com/mr-shifu/mpc-lib/protocols/cmp/config"
)

var _ round.Round = (*round5)(nil)

type round5 struct {
	*round4
	UpdatedConfig *config.Config

	// Number of Broacasted Messages received
	MessageBroadcasted map[party.ID]bool
}

type broadcast5 struct {
	round.NormalBroadcastContent
	// SchnorrResponse is the Schnorr proof of knowledge of the new secret share
	SchnorrResponse *sch.Response
}

// StoreBroadcastMessage implements round.BroadcastRound.
//
// - verify all Schnorr proof for the new ecdsa share.
func (r *round5) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcast5)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if !body.SchnorrResponse.IsValid() {
		return round.ErrNilFields
	}

	if !body.SchnorrResponse.Verify(r.HashForID(from),
		r.UpdatedConfig.Public[from].ECDSA,
		r.SchnorrCommitments[from], nil) {
		return errors.New("failed to validate schnorr proof for received share")
	}

	// Mark the message as received
	r.MessageBroadcasted[from] = true

	return nil
}

// VerifyMessage implements round.Round.
func (round5) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (r *round5) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round.
func (r *round5) Finalize(chan<- *round.Message) (round.Session, error) {
	// Verify if all parties commitments are received
	if len(r.MessageBroadcasted) != r.N()-1 {
		return nil, round.ErrNotEnoughMessages
	}
	return r.ResultRound(r.UpdatedConfig), nil
}

func (r *round5) CanFinalize() bool {
	// Verify if all parties commitments are received
	return len(r.MessageBroadcasted) == r.N()-1
}

// MessageContent implements round.Round.
func (r *round5) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcast5) RoundNumber() round.Number { return 5 }

// BroadcastContent implements round.BroadcastRound.
func (r *round5) BroadcastContent() round.BroadcastContent {
	return &broadcast5{
		SchnorrResponse: sch.EmptyResponse(r.Group()),
	}
}

// Number implements round.Round.
func (round5) Number() round.Number { return 5 }

type round5Serialized struct {
	Round4             []byte
	UpdatedConfig      []byte
	MessageBroadcasted map[party.ID]bool
}

func NewEmptyRound5(g curve.Curve, pl *pool.Pool) *round5 {
	return &round5{
		round4:             NewEmptyRound4(g, pl),
		UpdatedConfig:      config.NewEmptyConfig(g),
		MessageBroadcasted: make(map[party.ID]bool),
	}
}
func (r *round5) Serialize() (ser []byte, err error) {
	rs := round5Serialized{
		MessageBroadcasted: r.MessageBroadcasted,
	}

	rs.Round4, err = r.round4.Serialize()
	if err != nil {
		return nil, err
	}

	rs.UpdatedConfig, err = r.UpdatedConfig.Serialize()
	if err != nil {
		return nil, err
	}

	return json.Marshal(rs)
}
func (r *round5) Deserialize(data []byte) error {
	var rs round5Serialized
	if err := json.Unmarshal(data, &rs); err != nil {
		return err
	}

	if err := r.round4.Deserialize(rs.Round4); err != nil {
		return err
	}

	if err := r.UpdatedConfig.Deserialize(rs.UpdatedConfig); err != nil {
		return err
	}

	r.MessageBroadcasted = rs.MessageBroadcasted

	return nil
}
func (r *round5) Equal(other round.Round) bool {
	return true
}
