package keygen

import (
	"github.com/mr-shifu/mpc-lib/core/hash"
	"github.com/mr-shifu/mpc-lib/core/party"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/pkg/common/commitstore"
)

var _ round.Round = (*round2)(nil)

type round2 struct {
	*round1

	// Number of Broacasted Messages received
	MessageBroadcasted map[party.ID]bool
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
	cmt := &commitstore.Commitment{
		Commitment:   body.Commitment,
		Decommitment: nil,
	}
	if err := r.commit_mgr.Import(r.ID, msg.From, cmt); err != nil {
		return err
	}

	// Mark the message as received
	r.MessageBroadcasted[msg.From] = true

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
	if len(r.MessageBroadcasted) != r.N()-1 {
		return nil, round.ErrNotEnoughMessages
	}

	// TODO need keyID to get the key
	elgamalKey, err := r.elgamal_km.GetKey(r.ID, string(r.SelfID()))
	if err != nil {
		return nil, err
	}

	rid, err := r.rid_km.GetKey(r.ID, string(r.SelfID()))
	if err != nil {
		return nil, err
	}

	chainKey, err := r.chainKey_km.GetKey(r.ID, string(r.SelfID()))
	if err != nil {
		return nil, err
	}

	ecKey, err := r.ecdsa_km.GetKey(r.ID, string(r.SelfID()))
	if err != nil {
		return nil, err
	}
	schnorrCommitment, err := ecKey.SchnorrCommitment()
	if err != nil {
		return nil, err
	}
	vssKey, err := ecKey.VSS()
	if err != nil {
		return nil, err
	}

	exponents, err := vssKey.ExponentsRaw()
	if err != nil {
		return nil, err
	}

	paillier, err := r.paillier_km.GetKey(r.ID, string(r.SelfID()))
	if err != nil {
		return nil, err
	}

	ped, err := r.pedersen_km.GetKey(r.ID, string(r.SelfID()))
	if err != nil {
		return nil, err
	}

	// Send the message we created in Round1 to all
	cmt, err := r.commit_mgr.Get(r.ID, r.SelfID())
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
		Decommitment: cmt.Decommitment,
	})
	if err != nil {
		return r, err
	}
	return &round3{
		round2:             r,
		MessageBroadcasted: make(map[party.ID]bool),
	}, nil
}

func (r *round2) CanFinalize() bool {
	// Verify if all parties commitments are received
	return len(r.MessageBroadcasted) == r.N()-1
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
