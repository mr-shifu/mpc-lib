package keygen

import (
	"github.com/mr-shifu/mpc-lib/core/hash"
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

var _ round.Round = (*round2)(nil)

type round2 struct {
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
}

type broadcast2 struct {
	round.ReliableBroadcastContent
	// Commitment = Vᵢ = H(ρᵢ, Fᵢ(X), Aᵢ, Yᵢ, Nᵢ, sᵢ, tᵢ, uᵢ)
	Commitment hash.Commitment
}

// StoreBroadcastMessage implements round.BroadcastRound.
// - save commitment Vⱼ.
func (r *round2) StoreBroadcastMessage(msg round.Message) error {
	content, err := r.validateBroadcastMessage(msg)
	if err != nil {
		return errors.WithMessage(err, "keygen.round2.StoreBroadcastMessage: failed to validate message")
	}

	if err := content.Commitment.Validate(); err != nil {
		return err
	}

	fromOpts, err := keyopts.NewOptions().Set("id", r.ID, "partyid", string(msg.From))
	if err != nil {
		return errors.WithMessage(err, "keygen.round2.StoreBroadcastMessage: failed to create options")
	}

	cmt := r.commit_mgr.NewCommitment(content.Commitment, nil)
	if err := r.commit_mgr.Import(cmt, fromOpts); err != nil {
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

func (r *round2) validateBroadcastMessage(msg round.Message) (*broadcast2, error) {
	content, ok := msg.Content.(*broadcast2)
	if !ok || content == nil {
		return nil, round.ErrInvalidContent
	}
	if content.Commitment == nil {
		return nil, errors.New("keygen.round2.validateBroadcastMessage: commitment is nil")
	}
	return content, nil
}

// VerifyMessage implements round.Round.
func (round2) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (round2) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
//
// - send all committed data.
func (r *round2) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Verify if all parties commitments are received
	if !r.CanFinalize() {
		return nil, round.ErrNotEnoughMessages
	}

	opts, err := keyopts.NewOptions().Set("id", r.ID, "partyid", string(r.SelfID()))
	if err != nil {
		return nil, errors.WithMessage(err, "keygen.round2.Finalize: failed to create options")
	}

	// TODO need keyID to get the key
	elgamalKey, err := r.elgamal_km.GetKey(opts)
	if err != nil {
		return nil, err
	}

	rid, err := r.rid_km.GetKey(opts)
	if err != nil {
		return nil, err
	}

	chainKey, err := r.chainKey_km.GetKey(opts)
	if err != nil {
		return nil, err
	}

	ecKey, err := r.ecdsa_km.GetKey(opts)
	if err != nil {
		return nil, err
	}
	schnorrProof, err := r.ecdsa_km.GetSchnorrProof(opts)
	if err != nil {
		return nil, err
	}
	sch_byte, err := schnorrProof.Commitment().Bytes()
	if err != nil {
		return nil, err
	}

	vssKey, err := r.ecdsa_km.GetVss(opts)
	if err != nil {
		return nil, err
	}

	exponents, err := vssKey.ExponentsRaw()
	if err != nil {
		return nil, err
	}

	paillier, err := r.paillier_km.GetKey(opts)
	if err != nil {
		return nil, err
	}

	ped, err := r.pedersen_km.GetKey(opts)
	if err != nil {
		return nil, err
	}

	// Send the message we created in Round1 to all
	cmt, err := r.commit_mgr.Get(opts)
	if err != nil {
		return nil, err
	}

	ec_bytes, err := ecKey.PublicKey().Bytes()
	if err != nil {
		return nil, err
	}
	elgamal_bytes, err := elgamalKey.PublicKey().Bytes()
	if err != nil {
		return nil, err
	}
	paillier_bytes, err := paillier.PublicKey().Bytes()
	if err != nil {
		return nil, err
	}
	ped_bytes, err := ped.PublicKey().Bytes()
	if err != nil {
		return nil, err
	}
	exponents_bytes, err := exponents.MarshalBinary()
	if err != nil {
		return nil, err
	}

	err = r.BroadcastMessage(out, &broadcast3{
		RID:                rid.Raw(),
		C:                  chainKey.Raw(),
		EcdsaKey:           ec_bytes,
		VSSPolynomial:      exponents_bytes,
		SchnorrCommitments: sch_byte,
		PaillierKey:        paillier_bytes,
		ElgamalKey:         elgamal_bytes,
		PedersenKey:        ped_bytes,
		Decommitment:       cmt.Decommitment(),
	})
	if err != nil {
		return r, err
	}

	// update last round processed in StateManager
	if err := r.statemanger.SetLastRound(r.ID, int(r.Number())); err != nil {
		return r, err
	}

	return &round3{
		Helper:      r.Helper,
		statemanger: r.statemanger,
		msgmgr:      r.msgmgr,
		bcstmgr:     r.bcstmgr,
		elgamal_km:  r.elgamal_km,
		paillier_km: r.paillier_km,
		pedersen_km: r.pedersen_km,
		ecdsa_km:    r.ecdsa_km,
		ec_vss_km:   r.ec_vss_km,
		vss_mgr:     r.vss_mgr,
		rid_km:      r.rid_km,
		chainKey_km: r.chainKey_km,
		commit_mgr:  r.commit_mgr,
	}, nil
}

func (r *round2) CanFinalize() bool {
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

// PreviousRound implements round.Round.
// func (r *round2) PreviousRound() round.Round { return r.round1 }

// MessageContent implements round.Round.
func (round2) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcast2) RoundNumber() round.Number { return 2 }

// BroadcastContent implements round.BroadcastRound.
func (round2) BroadcastContent() round.BroadcastContent { return &broadcast2{} }

// Number implements round.Round.
func (round2) Number() round.Number { return 2 }
