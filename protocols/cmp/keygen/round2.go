package keygen

import (
	"github.com/mr-shifu/mpc-lib/core/hash"
	"github.com/mr-shifu/mpc-lib/core/party"
	zksch "github.com/mr-shifu/mpc-lib/core/zk/sch"
	"github.com/mr-shifu/mpc-lib/lib/round"
	comm_elgamal "github.com/mr-shifu/mpc-lib/pkg/mpc/common/elgamal"
	comm_mpc_ks "github.com/mr-shifu/mpc-lib/pkg/mpc/common/mpckey"
	comm_paillier "github.com/mr-shifu/mpc-lib/pkg/mpc/common/paillier"
	comm_pedersen "github.com/mr-shifu/mpc-lib/pkg/mpc/common/pedersen"
	comm_rid "github.com/mr-shifu/mpc-lib/pkg/mpc/common/rid"
	comm_vss "github.com/mr-shifu/mpc-lib/pkg/mpc/common/vss"
)

var _ round.Round = (*round2)(nil)

type round2 struct {
	*round1

	mpc_ks      comm_mpc_ks.MPCKeystore
	elgamal_km  comm_elgamal.ElgamalKeyManager
	paillier_km comm_paillier.PaillierKeyManager
	pedersen_km comm_pedersen.PedersenKeyManager
	vss_km      comm_vss.VssKeyManager
	rid_km      comm_rid.RIDKeyManager
	chainKey_km comm_rid.RIDKeyManager

	// Commitments[j] = H(Keygen3ⱼ ∥ Decommitments[j])
	Commitments map[party.ID]hash.Commitment

	// SchnorrRand = aᵢ
	// Randomness used to compute Schnorr commitment of proof of knowledge of secret share
	SchnorrRand *zksch.Randomness

	// Decommitment for Keygen3ᵢ
	Decommitment hash.Decommitment // uᵢ

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
	r.Commitments[msg.From] = body.Commitment
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
	elgamalKey, err := r.elgamal_km.GetKey(r.KeyID, string(r.SelfID()))
	if err != nil {
		return nil, err
	}
	ekb, err := elgamalKey.Bytes()
	if err != nil {
		return nil, err
	}

	rid, err := r.rid_km.GetKey(r.KeyID, string(r.SelfID()))
	if err != nil {
		return nil, err
	}

	chainKey, err := r.chainKey_km.GetKey(r.KeyID, string(r.SelfID()))
	if err != nil {
		return nil, err
	}

	vsspoly, err := r.vss_km.GetKey(r.KeyID, string(r.SelfID()))
	if err != nil {
		return nil, err
	}
	exponents, err := vsspoly.ExponentsRaw()
	if err != nil {
		return nil, err
	}

	ped, err := r.pedersen_km.GetKey(r.KeyID, string(r.SelfID()))
	if err != nil {
		return nil, err
	}

	// Send the message we created in Round1 to all
	err = r.BroadcastMessage(out, &broadcast3{
		RID:                rid.Raw(),
		C:                  chainKey.Raw(),
		VSSPolynomial:      exponents,
		SchnorrCommitments: r.SchnorrRand.Commitment(),
		ElGamalPublic:      ekb,
		N:                  ped.PublicKeyRaw().N(),
		S:                  ped.PublicKeyRaw().S(),
		T:                  ped.PublicKeyRaw().T(),
		Decommitment:       r.Decommitment,
	})
	if err != nil {
		return r, err
	}
	return &round3{
		round2:             r,
		mpc_ks:             r.mpc_ks,
		elgamal_km:         r.elgamal_km,
		paillier_km:        r.paillier_km,
		pedersen_km:        r.pedersen_km,
		vss_km:             r.vss_km,
		rid_km:             r.rid_km,
		chainKey_km:        r.chainKey_km,
		SchnorrCommitments: map[party.ID]*zksch.Commitment{},
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
