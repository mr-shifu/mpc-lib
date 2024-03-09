package sign

import (
	"errors"

	"github.com/cronokirby/saferith"
	"github.com/mr-shifu/mpc-lib/core/paillier"
	"github.com/mr-shifu/mpc-lib/core/party"
	zkenc "github.com/mr-shifu/mpc-lib/core/zk/enc"
	"github.com/mr-shifu/mpc-lib/lib/round"
	sw_mta "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/mta"
	pek "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillierencodedkey"
)

var _ round.Round = (*round2)(nil)

type round2 struct {
	*round1

	// Number of Broacasted Messages received
	MessageBroadcasted map[party.ID]bool
}

type broadcast2 struct {
	round.ReliableBroadcastContent
	// K = Kᵢ
	K *paillier.Ciphertext
	// G = Gᵢ
	G *paillier.Ciphertext
}

type message2 struct {
	ProofEnc *zkenc.Proof
}

// StoreBroadcastMessage implements round.Round.
//
// - store Kⱼ, Gⱼ.
func (r *round2) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcast2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	paillierj, err := r.paillier_km.GetKey(r.ID, string(from))
	if err != nil {
		return err
	}

	if !paillierj.ValidateCiphertexts(body.K, body.G) {
		return errors.New("invalid K, G")
	}

	k_pekj := pek.NewPaillierEncodedkey(nil, body.K, nil)
	KShare, err := r.signK.GetKey(r.ID, string(from))
	if err != nil {
		return err
	}
	if err := KShare.ImportPaillierEncoded(k_pekj); err != nil {
		return nil
	}

	gamma_pekj := pek.NewPaillierEncodedkey(nil, body.G, nil)
	gamma, err := r.gamma.GetKey(r.ID, string(from))
	if err := gamma.ImportPaillierEncoded(gamma_pekj); err != nil {
		return nil
	}

	// Mark the message as received
	r.MessageBroadcasted[from] = true

	return nil
}

// VerifyMessage implements round.Round.
//
// - verify zkenc(Kⱼ).
func (r *round2) VerifyMessage(msg round.Message) error {
	from, to := msg.From, msg.To
	body, ok := msg.Content.(*message2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if body.ProofEnc == nil {
		return round.ErrNilFields
	}

	paillierFrom, err := r.paillier_km.GetKey(r.ID, string(from))
	if err != nil {
		return err
	}
	pedersenTo, err := r.pedersen_km.GetKey(r.ID, string(to))
	if err != nil {
		return err
	}
	KShare, err := r.signK.GetKey(r.ID, string(from))
	Kj, err := KShare.GetPaillierEncodedKey()
	if err != nil {
		return err
	}
	if !body.ProofEnc.Verify(r.Group(), r.HashForID(from), zkenc.Public{
		K:      Kj.Encoded(),
		Prover: paillierFrom.PublicKeyRaw(),
		Aux:    pedersenTo.PublicKeyRaw(),
	}) {
		return errors.New("failed to validate enc proof for K")
	}
	return nil
}

// StoreMessage implements round.Round.
//
// - store Kⱼ, Gⱼ.
func (round2) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
//
// - compute Hash(ssid, K₁, G₁, …, Kₙ, Gₙ).
func (r *round2) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Verify if all parties commitments are received
	if len(r.MessageBroadcasted) != r.N()-1 {
		return nil, round.ErrNotEnoughMessages
	}

	// Retreive Gamma key from keystore
	gamma, err := r.gamma.GetKey(r.cfg.ID(), string(r.SelfID()))
	if err != nil {
		return r, err
	}

	if err := r.BroadcastMessage(out, &broadcast3{
		BigGammaShare: gamma.PublicKeyRaw(),
	}); err != nil {
		return r, err
	}

	otherIDs := r.OtherPartyIDs()
	type mtaOut struct {
		err       error
		DeltaBeta *saferith.Int
		ChiBeta   *saferith.Int
	}
	mtaOuts := r.Pool.Parallelize(len(otherIDs), func(i int) interface{} {
		j := otherIDs[i]

		// TODO must be changed to signID
		gamma, err := r.gamma.GetKey(r.cfg.ID(), string(j))
		if err != nil {
			return err
		}
		ShareK, err := r.signK.GetKey(r.cfg.ID(), string(j))
		if err != nil {
			return err
		}
		k_pek, err := ShareK.GetPaillierEncodedKey()
		if err != nil {
			return err
		}
		paillierKey, err := r.paillier_km.GetKey(r.cfg.KeyID(), string(r.SelfID()))
		if err != nil {
			return err
		}
		paillierj, err := r.paillier_km.GetKey(r.cfg.KeyID(), string(j))
		if err != nil {
			return err
		}
		pedj, err := r.pedersen_km.GetKey(r.cfg.KeyID(), string(j))
		if err != nil {
			return err
		}

		DeltaBeta, DeltaD, DeltaF, DeltaProof := gamma.NewMtAAffgProof(
			r.HashForID(r.SelfID()),
			k_pek.Encoded(),
			paillierKey.PublicKey(),
			paillierj.PublicKey(),
			pedj.PublicKey(),
		)

		ChiBeta, ChiD, ChiF, ChiProof := gamma.NewMtAAffgProof(
			r.HashForID(r.SelfID()),
			k_pek.Encoded(),
			paillierKey.PublicKey(),
			paillierj.PublicKey(),
			pedj.PublicKey(),
		)

		gammaPEK, err := gamma.GetPaillierEncodedKey()
		if err != nil {
			return err
		}
		proof, err := gamma.NewZKLogstarProof(
			r.HashForID(r.SelfID()),
			gammaPEK.Encoded(),   // G
			gamma.PublicKeyRaw(), // Gamma
			nil,
			paillierKey.PublicKey(),
			pedj.PublicKey(),
		)
		if err != nil {
			return err
		}

		err = r.SendMessage(out, &message3{
			DeltaD:     DeltaD,
			DeltaF:     DeltaF,
			DeltaProof: DeltaProof,
			ChiD:       ChiD,
			ChiF:       ChiF,
			ChiProof:   ChiProof,
			ProofLog:   proof,
		}, j)
		return mtaOut{
			err:       err,
			DeltaBeta: DeltaBeta,
			ChiBeta:   ChiBeta,
		}
	})

	for idx, mtaOutRaw := range mtaOuts {
		j := otherIDs[idx]
		m := mtaOutRaw.(mtaOut)
		if m.err != nil {
			return r, m.err
		}
		delta_mta := sw_mta.NewMtA(nil, m.DeltaBeta)
		if _, err := r.delta_mta.ImportKey(r.cfg.ID(), string(j), delta_mta); err != nil {
			return nil, err
		}
		chi_mta := sw_mta.NewMtA(nil, m.ChiBeta)
		if _, err := r.chi_mta.ImportKey(r.cfg.ID(), string(j), chi_mta); err != nil {
			return nil, err
		}
	}

	return &round3{
		round2:             r,
		MessageBroadcasted: make(map[party.ID]bool),
		MessageForwarded:   make(map[party.ID]bool),
	}, nil
}

func (r *round2) CanFinalize() bool {
	// Verify if all parties commitments are received
	return len(r.MessageBroadcasted) == r.N()-1
}

// RoundNumber implements round.Content.
func (message2) RoundNumber() round.Number { return 2 }

// MessageContent implements round.Round.
func (round2) MessageContent() round.Content { return &message2{} }

// RoundNumber implements round.Content.
func (broadcast2) RoundNumber() round.Number { return 2 }

// BroadcastContent implements round.BroadcastRound.
func (round2) BroadcastContent() round.BroadcastContent { return &broadcast2{} }

// Number implements round.Round.
func (round2) Number() round.Number { return 2 }

func (r *round2) Equal(other round.Round) bool {
	return true
}
