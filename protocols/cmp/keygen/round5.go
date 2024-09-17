package keygen

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/commitment"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/elgamal"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillier"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/pedersen"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/rid"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/message"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/state"
	"github.com/pkg/errors"
)

var _ round.Round = (*round5)(nil)

type round5 struct {
	*round.Helper

	statemanger state.MPCStateManager
	msgmgr      message.MessageManager
	bcstmgr     message.MessageManager
	elgamal_km  elgamal.ElgamalKeyManager
	paillier_km paillier.PaillierKeyManager
	pedersen_km pedersen.PedersenKeyManager
	ecdsa_km    ecdsa.ECDSAKeyManager
	ec_vss_km   ecdsa.ECDSAKeyManager
	vss_mgr     vss.VssKeyManager
	rid_km      rid.RIDManager
	chainKey_km rid.RIDManager
	commit_mgr  commitment.CommitmentManager

	UpdatedConfig *Config
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

	fromOpts, err := keyopts.NewOptions().Set("id", r.ID, "partyid", string(from))
	if err != nil {
		return errors.WithMessage(err, "keygen.round5.StoreBroadcastMessage: failed to create options")
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

	zb, _ := body.SchnorrResponse.MarshalBinary()
	if err := r.ecdsa_km.ImportSchnorrProofResponse(zb, fromOpts); err != nil {
		return errors.WithMessage(err, "failed to import schnorr proof response")
	}
	verified, err := r.ecdsa_km.VerifySchnorrProof(r.HashForID(from), fromOpts)
	if err != nil {
		return err
	}
	if !verified {
		return errors.New("failed to validate schnorr proof for received share")
	}

	// update last round processed in StateManager
	if err := r.statemanger.SetLastRound(r.ID, int(r.Number())); err != nil {
		return err
	}
	// update state to Completed in StateManager
	if err := r.statemanger.SetCompleted(r.ID, true); err != nil {
		return err
	}

	// Mark the message as received
	if err := r.bcstmgr.Import(
		r.bcstmgr.NewMessage(r.ID, int(r.Number()), string(msg.From), true),
	); err != nil {
		return err
	}

	return nil
}

// VerifyMessage implements round.Round.
func (round5) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (r *round5) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round.
func (r *round5) Finalize(chan<- *round.Message) (round.Session, error) {
	// Verify if all parties commitments are received
	if !r.CanFinalize() {
		return nil, round.ErrNotEnoughMessages
	}
	return r.ResultRound(r.UpdatedConfig), nil
}

func (r *round5) CanFinalize() bool {
	// Verify if all parties commitments are received
	var parties []string
	for _, p := range r.OtherPartyIDs() {
		parties = append(parties, string(p))
	}
	rcvd, err := r.bcstmgr.HasAll(r.ID, int(r.Number()), parties)
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
		SchnorrResponse: r.Group().NewScalar(), // sch.EmptyResponse(r.Group()),
	}
}

// Number implements round.Round.
func (round5) Number() round.Number { return 5 }
