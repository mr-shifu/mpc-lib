package keygen

import (
	"github.com/mr-shifu/mpc-lib/core/hash"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
)

var _ round.Round = (*round2)(nil)

type round2 struct {
	*round1
}

type broadcast2 struct {
	round.ReliableBroadcastContent
	// Commitment = Vᵢ = H(ρᵢ, Fᵢ(X), Aᵢ, Yᵢ, Nᵢ, sᵢ, tᵢ, uᵢ)
	Commitment hash.Commitment
}

// StoreBroadcastMessage implements round.BroadcastRound.
// - save commitment Vⱼ.
func (r *round2) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*broadcast2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	if err := body.Commitment.Validate(); err != nil {
		return err
	}

	fromOpts := keyopts.Options{}
	fromOpts.Set("id", r.ID, "partyid", string(msg.From))

	cmt := r.commit_mgr.NewCommitment(body.Commitment, nil)
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

// VerifyMessage implements round.Round.
func (round2) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (round2) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
//
// - send all committed data.
func (r *round2) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Verify if all parties commitments are received
	if r.CanFinalize() == false {
		return nil, round.ErrNotEnoughMessages
	}

	opts := keyopts.Options{}
	opts.Set("id", r.ID, "partyid", string(r.SelfID()))

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
	schnorrCommitment, err := ecKey.SchnorrCommitment()
	if err != nil {
		return nil, err
	}
	vssKey, err := ecKey.VSS(opts)
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
		SchnorrCommitments: schnorrCommitment,
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
		round2: r,
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
func (r *round2) PreviousRound() round.Round { return r.round1 }

// MessageContent implements round.Round.
func (round2) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcast2) RoundNumber() round.Number { return 2 }

// BroadcastContent implements round.BroadcastRound.
func (round2) BroadcastContent() round.BroadcastContent { return &broadcast2{} }

// Number implements round.Round.
func (round2) Number() round.Number { return 2 }
