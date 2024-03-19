package sign

import (
	"errors"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/party"
	zklogstar "github.com/mr-shifu/mpc-lib/core/zk/logstar"
	"github.com/mr-shifu/mpc-lib/lib/round"
	comm_ecdsa "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/ecdsa"
	sw_ecdsa "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ecdsa"
)

var _ round.Round = (*round4)(nil)

type round4 struct {
	*round3

	// Number of Broacasted Messages received
	MessageBroadcasted map[party.ID]bool
}

type message4 struct {
	ProofLog *zklogstar.Proof
}

type broadcast4 struct {
	round.NormalBroadcastContent
	// DeltaShare = δⱼ
	DeltaShare curve.Scalar
	// BigDeltaShare = Δⱼ = [kⱼ]•Γⱼ
	BigDeltaShare curve.Point
}

// StoreBroadcastMessage implements round.BroadcastRound.
//
// - store δⱼ, Δⱼ
func (r *round4) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*broadcast4)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	if body.DeltaShare.IsZero() || body.BigDeltaShare.IsIdentity() {
		return round.ErrNilFields
	}

	bigDeltaShareFrom := body.BigDeltaShare
	bigDeltaFrom := sw_ecdsa.NewECDSAKey(nil, bigDeltaShareFrom, bigDeltaShareFrom.Curve())
	if err := r.bigDelta.ImportKey(r.cfg.ID(), string(msg.From), bigDeltaFrom); err != nil {
		return err
	}

	deltaShareFrom := body.DeltaShare
	deltaFrom := sw_ecdsa.NewECDSAKey(deltaShareFrom, deltaShareFrom.Act(deltaShareFrom.Curve().NewBasePoint()), deltaShareFrom.Curve())
	if err := r.delta.ImportKey(r.cfg.ID(), string(msg.From), deltaFrom); err != nil {
		return err
	}

	// Mark the message as received
	r.MessageBroadcasted[msg.From] = true

	return nil
}

// VerifyMessage implements round.Round.
//
// - Verify Π(log*)(ϕ”ᵢⱼ, Δⱼ, Γ).
func (r *round4) VerifyMessage(msg round.Message) error {
	from, to := msg.From, msg.To
	body, ok := msg.Content.(*message4)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	kFromPek, err := r.signK_pek.GetKey(r.cfg.ID(), string(from))
	if err != nil {
		return err
	}

	bigDeltaShareFrom, err := r.bigDelta.GetKey(r.cfg.ID(), string(from))
	if err != nil {
		return err
	}

	gamma, err := r.gamma.GetKey(r.cfg.ID(), "ROOT")
	if err != nil {
		return err
	}

	paillierFrom, err := r.paillier_km.GetKey(r.cfg.KeyID(), string(from))
	if err != nil {
		return err
	}
	pedTo, err := r.pedersen_km.GetKey(r.cfg.KeyID(), string(to))
	if err != nil {
		return err
	}

	zkLogPublic := zklogstar.Public{
		C:      kFromPek.Encoded(),
		X:      bigDeltaShareFrom.PublicKeyRaw(),
		G:      gamma.PublicKeyRaw(),
		Prover: paillierFrom.PublicKeyRaw(),
		Aux:    pedTo.PublicKeyRaw(),
	}
	if !body.ProofLog.Verify(r.HashForID(from), zkLogPublic) {
		return errors.New("failed to validate log proof")
	}

	return nil
}

// StoreMessage implements round.Round.
func (round4) StoreMessage(round.Message) error {
	return nil
}

// Finalize implements round.Round
//
// - set δ = ∑ⱼ δⱼ
// - set Δ = ∑ⱼ Δⱼ
// - verify Δ = [δ]G
// - compute σᵢ = rχᵢ + kᵢm.
func (r *round4) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Verify if all parties commitments are received
	if len(r.MessageBroadcasted) != r.N()-1 {
		return nil, round.ErrNotEnoughMessages
	}

	// δ = ∑ⱼ δⱼ
	var deltaShares []comm_ecdsa.ECDSAKey
	for _, j := range r.OtherPartyIDs() {
		delta, err := r.delta.GetKey(r.cfg.ID(), string(j))
		if err != nil {
			return nil, err
		}
		deltaShares = append(deltaShares, delta)
	}
	selfdeltaShare, err := r.delta.GetKey(r.cfg.ID(), string(r.SelfID()))
	if err != nil {
		return nil, err
	}
	Delta := selfdeltaShare.AddKeys(deltaShares...)

	// Δ = ∑ⱼ Δⱼ
	BigDelta := r.Group().NewPoint()
	for _, j := range r.PartyIDs() {
		bigDeltaj, err := r.bigDelta.GetKey(r.cfg.ID(), string(j))
		if err != nil {
			return nil, err
		}
		BigDelta = BigDelta.Add(bigDeltaj.PublicKeyRaw())
	}

	// Δ == [δ]G
	deltaComputed := Delta.ActOnBase()
	if !deltaComputed.Equal(BigDelta) {
		return r.AbortRound(errors.New("computed Δ is inconsistent with [δ]G")), nil
	}

	// R = [δ⁻¹] Γ
	gamma, err := r.gamma.GetKey(r.cfg.ID(), "ROOT")
	if err != nil {
		return nil, err
	}
	deltaInv := r.Group().NewScalar().Set(Delta).Invert() // δ⁻¹
	BigR := deltaInv.Act(gamma.PublicKeyRaw())            // R = [δ⁻¹] Γ
	R := BigR.XScalar()                                   // r = R|ₓ

	// rχᵢ
	chiShare, err := r.chi.GetKey(r.cfg.ID(), string(r.SelfID()))
	if err != nil {
		return nil, err
	}
	RChi := chiShare.Mul(R)

	// km = Hash(m)⋅kᵢ
	// σᵢ = rχᵢ + kᵢm
	m := curve.FromHash(r.Group(), r.Message)
	selfKShare, err := r.signK.GetKey(r.cfg.ID(), string(r.SelfID()))
	if err != nil {
		return nil, err
	}
	SigmaShare := selfKShare.Commit(m, RChi)
	if err := r.sigma.ImportSigma(r.cfg.ID(), string(r.SelfID()), SigmaShare); err != nil {
		return nil, err
	}
	r.signature.ImportSignR(r.cfg.ID(), BigR)

	// Send to all
	err = r.BroadcastMessage(out, &broadcast5{SigmaShare: SigmaShare})
	if err != nil {
		return r, err
	}
	return &round5{
		round4:             r,
		MessageBroadcasted: make(map[party.ID]bool),
	}, nil
}

func (r *round4) CanFinalize() bool {
	// Verify if all parties commitments are received
	return len(r.MessageBroadcasted) == r.N()-1
}

// RoundNumber implements round.Content.
func (message4) RoundNumber() round.Number { return 4 }

// MessageContent implements round.Round.
func (r *round4) MessageContent() round.Content {
	return &message4{
		ProofLog: zklogstar.Empty(r.Group()),
	}
}

// RoundNumber implements round.Content.
func (broadcast4) RoundNumber() round.Number { return 4 }

// BroadcastContent implements round.BroadcastRound.
func (r *round4) BroadcastContent() round.BroadcastContent {
	return &broadcast4{
		DeltaShare:    r.Group().NewScalar(),
		BigDeltaShare: r.Group().NewPoint(),
	}
}

// Number implements round.Round.
func (round4) Number() round.Number { return 4 }

func (r *round4) Equal(other round.Round) bool {
	return true
}
