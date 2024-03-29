package keygen

import (
	"errors"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/party"
	"github.com/mr-shifu/mpc-lib/lib/round"
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
	SchnorrResponse curve.Scalar
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

	// TODO implement SchnorrResponse validation
	// if !body.SchnorrResponse.IsValid() {
	// 	return round.ErrNilFields
	// }

	// if !body.SchnorrResponse.Verify(r.HashForID(from),
	// 	r.UpdatedConfig.Public[from].ECDSA,
	// 	r.SchnorrCommitments[from], nil) {
	// 	return errors.New("failed to validate schnorr proof for received share")
	// }
	ecKey, err := r.ecdsa_km.GetKey(r.ID, string(from))
	if err != nil {
		return err
	}

	verified, err := ecKey.VerifySchnorrProof(r.HashForID(from), body.SchnorrResponse)
	if err != nil {
		return err
	}
	if !verified {
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
		SchnorrResponse: r.Group().NewScalar(), // sch.EmptyResponse(r.Group()),
	}
}

// Number implements round.Round.
func (round5) Number() round.Number { return 5 }
