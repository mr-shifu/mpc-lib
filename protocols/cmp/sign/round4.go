package sign

import (
	"errors"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
	zklogstar "github.com/mr-shifu/mpc-lib/core/zk/logstar"
	"github.com/mr-shifu/mpc-lib/lib/round"
	comm_ecdsa "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/ecdsa"
	sw_ecdsa "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
)

var _ round.Round = (*round4)(nil)

type round4 struct {
	*round3
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

	soptsFrom := keyopts.Options{}
	soptsFrom.Set("id", r.cfg.ID(), "partyid", string(msg.From))

	bigDeltaShareFrom := body.BigDeltaShare
	bigDeltaFrom := sw_ecdsa.NewECDSAKey(nil, bigDeltaShareFrom, bigDeltaShareFrom.Curve())
	if _, err := r.bigDelta.ImportKey(bigDeltaFrom, soptsFrom); err != nil {
		return err
	}

	deltaShareFrom := body.DeltaShare
	deltaFrom := sw_ecdsa.NewECDSAKey(deltaShareFrom, deltaShareFrom.Act(deltaShareFrom.Curve().NewBasePoint()), deltaShareFrom.Curve())
	if _, err := r.delta.ImportKey(deltaFrom, soptsFrom); err != nil {
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
//
// - Verify Π(log*)(ϕ”ᵢⱼ, Δⱼ, Γ).
func (r *round4) VerifyMessage(msg round.Message) error {
	from, to := msg.From, msg.To
	body, ok := msg.Content.(*message4)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	koptsFrom := keyopts.Options{}
	koptsFrom.Set("id", r.cfg.KeyID(), "partyid", string(from))

	koptsTo := keyopts.Options{}
	koptsTo.Set("id", r.cfg.KeyID(), "partyid", string(to))

	soptsFrom := keyopts.Options{}
	soptsFrom.Set("id", r.cfg.ID(), "partyid", string(from))

	soptsRoot := keyopts.Options{}
	soptsRoot.Set("id", r.cfg.ID(), "partyid", string("ROOT"))

	kFromPek, err := r.signK_pek.Get(soptsFrom)
	if err != nil {
		return err
	}

	bigDeltaShareFrom, err := r.bigDelta.GetKey(soptsFrom)
	if err != nil {
		return err
	}

	gamma, err := r.gamma.GetKey(soptsRoot)
	if err != nil {
		return err
	}

	paillierFrom, err := r.paillier_km.GetKey(koptsFrom)
	if err != nil {
		return err
	}
	pedTo, err := r.pedersen_km.GetKey(koptsTo)
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
	if !r.CanFinalize() {
		return nil, round.ErrNotEnoughMessages
	}

	sopts := keyopts.Options{}
	sopts.Set("id", r.cfg.ID(), "partyid", string(r.SelfID()))

	soptsRoot := keyopts.Options{}
	soptsRoot.Set("id", r.cfg.ID(), "partyid", "ROOT")

	// δ = ∑ⱼ δⱼ
	var deltaShares []comm_ecdsa.ECDSAKey
	for _, j := range r.OtherPartyIDs() {
		soptsj := keyopts.Options{}
		soptsj.Set("id", r.cfg.ID(), "partyid", string(j))
		delta, err := r.delta.GetKey(soptsj)
		if err != nil {
			return nil, err
		}
		deltaShares = append(deltaShares, delta)
	}
	selfdeltaShare, err := r.delta.GetKey(sopts)
	if err != nil {
		return nil, err
	}
	Delta := selfdeltaShare.AddKeys(deltaShares...)

	// Δ = ∑ⱼ Δⱼ
	BigDelta := r.Group().NewPoint()
	for _, j := range r.PartyIDs() {
		soptsj := keyopts.Options{}
		soptsj.Set("id", r.cfg.ID(), "partyid", string(j))
		bigDeltaj, err := r.bigDelta.GetKey(soptsj)
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
	gamma, err := r.gamma.GetKey(soptsRoot)
	if err != nil {
		return nil, err
	}
	deltaInv := r.Group().NewScalar().Set(Delta).Invert() // δ⁻¹
	BigR := deltaInv.Act(gamma.PublicKeyRaw())            // R = [δ⁻¹] Γ
	R := BigR.XScalar()                                   // r = R|ₓ

	// rχᵢ
	chiShare, err := r.chi.GetKey(sopts)
	if err != nil {
		return nil, err
	}
	RChi := chiShare.Mul(R)

	// km = Hash(m)⋅kᵢ
	// σᵢ = rχᵢ + kᵢm
	m := curve.FromHash(r.Group(), r.Message)
	selfKShare, err := r.signK.GetKey(sopts)
	if err != nil {
		return nil, err
	}
	SigmaShare := selfKShare.Commit(m, RChi)
	if err := r.sigma.ImportSigma(SigmaShare, sopts); err != nil {
		return nil, err
	}
	r.signature.ImportSignR(r.cfg.ID(), BigR)

	// Send to all
	err = r.BroadcastMessage(out, &broadcast5{SigmaShare: SigmaShare})
	if err != nil {
		return r, err
	}

	// update last round processed in StateManager
	if err := r.statemgr.SetLastRound(r.ID, int(r.Number())); err != nil {
		return r, err
	}

	return &round5{
		round4: r,
	}, nil
}

func (r *round4) CanFinalize() bool {
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
