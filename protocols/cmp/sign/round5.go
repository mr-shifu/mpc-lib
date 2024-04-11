package sign

import (
	"errors"

	"github.com/mr-shifu/mpc-lib/core/ecdsa"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
)

var _ round.Round = (*round5)(nil)

type round5 struct {
	*round4
}

type broadcast5 struct {
	round.NormalBroadcastContent
	SigmaShare curve.Scalar
}

// StoreBroadcastMessage implements round.BroadcastRound.
//
// - save σⱼ
func (r *round5) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*broadcast5)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if body.SigmaShare.IsZero() {
		return round.ErrNilFields
	}

	soptsFrom := keyopts.Options{}
	soptsFrom.Set("id", r.cfg.ID(), "partyid", string(msg.From))

	// r.SigmaShares[msg.From] = body.SigmaShare
	if err := r.sigma.ImportSigma(body.SigmaShare, soptsFrom); err != nil {
		return err
	}

	// Mark the message as received
	if err := r.bcstmgr.Import(
		r.bcstmgr.NewMessage(r.cfg.ID(), int(r.Number()), string(msg.From), true),
	); err != nil {
		return err
	}

	return nil
}

// VerifyMessage implements round.Round.
func (round5) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (round5) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
//
// - compute σ = ∑ⱼ σⱼ
// - verify signature.
func (r *round5) Finalize(chan<- *round.Message) (round.Session, error) {
	// Verify if all parties commitments are received
	if !r.CanFinalize() {
		return nil, round.ErrNotEnoughMessages
	}

	soptsRoot := keyopts.Options{}
	soptsRoot.Set("id", r.cfg.ID(), "partyid", string("ROOT"))

	koptsRoot := keyopts.Options{}
	koptsRoot.Set("id", r.cfg.KeyID(), "partyid", string("ROOT"))

	// compute σ = ∑ⱼ σⱼ
	Sigma := r.Group().NewScalar()
	for _, j := range r.PartyIDs() {
		soptsj := keyopts.Options{}
		soptsj.Set("id", r.cfg.ID(), "partyid", string(j))
		sigmaShare, err := r.sigma.GetSigma(soptsj)
		if err != nil {
			return nil, err
		}
		Sigma = Sigma.Add(sigmaShare)
	}

	r.signature.ImportSignSigma(r.cfg.ID(), Sigma)
	signR := r.signature.SignR(r.cfg.ID())

	signature := &ecdsa.Signature{
		R: signR,
		S: Sigma,
	}

	ecKey, err := r.ec.GetKey(soptsRoot)
	if err != nil {
		return nil, err
	}
	if !signature.Verify(ecKey.PublicKeyRaw(), r.Message) {
		// update state to Aborted in StateManager
		if err := r.statemgr.SetAborted(r.ID); err != nil {
			return r, err
		}
		return r.AbortRound(errors.New("failed to validate signature")), nil
	}

	ecKey, err = r.ec.GetKey(koptsRoot)
	if err != nil {
		return nil, err
	}
	if !signature.Verify(ecKey.PublicKeyRaw(), r.Message) {
		// update state to Aborted in StateManager
		if err := r.statemgr.SetAborted(r.ID); err != nil {
			return r, err
		}
		return r.AbortRound(errors.New("failed to validate signature")), nil
	}

	// update last round processed in StateManager
	if err := r.statemgr.SetLastRound(r.ID, int(r.Number())); err != nil {
		return r, err
	}
	// update state to Completed in StateManager
	if err := r.statemgr.SetCompleted(r.ID); err != nil {
		return r, err
	}

	return r.ResultRound(signature), nil
}

func (r *round5) CanFinalize() bool {
	// Verify if all parties commitments are received
	var parties []string
	for _, p := range r.OtherPartyIDs() {
		parties = append(parties, string(p))
	}
	rcvd, err := r.bcstmgr.HasAll(r.cfg.ID(), int(r.Number()), parties)
	if err != nil {
		return false
	}
	return rcvd
}

// MessageContent implements round.Round.
func (r *round5) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcast5) RoundNumber() round.Number { return 5 }

// BroadcastContent implements round.BroadcastRound.
func (r *round5) BroadcastContent() round.BroadcastContent {
	return &broadcast5{
		SigmaShare: r.Group().NewScalar(),
	}
}

// Number implements round.Round.
func (round5) Number() round.Number { return 5 }

func (r *round5) Equal(other round.Round) bool {
	return true
}
