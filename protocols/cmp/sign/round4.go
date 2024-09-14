package sign

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	zklogstar "github.com/mr-shifu/mpc-lib/core/zk/logstar"
	"github.com/mr-shifu/mpc-lib/lib/round"
	com_keyopts "github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/mta"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillier"
	pek "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillierencodedkey"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/pedersen"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/config"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/message"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/result"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/state"
	"github.com/pkg/errors"
)

var _ round.Round = (*round4)(nil)

type round4 struct {
	*round.Helper

	cfg       config.SignConfig
	statemgr  state.MPCStateManager
	signature result.Signature
	msgmgr    message.MessageManager
	bcstmgr   message.MessageManager

	hash_mgr    hash.HashManager
	paillier_km paillier.PaillierKeyManager
	pedersen_km pedersen.PedersenKeyManager

	ec       ecdsa.ECDSAKeyManager
	ec_vss   ecdsa.ECDSAKeyManager
	gamma    ecdsa.ECDSAKeyManager
	signK    ecdsa.ECDSAKeyManager
	delta    ecdsa.ECDSAKeyManager
	chi      ecdsa.ECDSAKeyManager
	bigDelta ecdsa.ECDSAKeyManager

	vss_mgr vss.VssKeyManager

	gamma_pek pek.PaillierEncodedKeyManager
	signK_pek pek.PaillierEncodedKeyManager

	delta_mta mta.MtAManager
	chi_mta   mta.MtAManager

	sigma result.SigmaStore
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

	soptsFrom, err := keyopts.NewOptions().Set("id", r.cfg.ID(), "partyid", string(msg.From))
	if err != nil {
		return errors.WithMessage(err, "sign.round4.StoreBroadcastMessage: failed to create options")
	}

	bigDeltaShareFrom := body.BigDeltaShare
	bigDeltaFrom := ecdsa.NewKey(nil, bigDeltaShareFrom, bigDeltaShareFrom.Curve())
	if _, err := r.bigDelta.ImportKey(bigDeltaFrom, soptsFrom); err != nil {
		return err
	}

	deltaShareFrom := body.DeltaShare
	deltaFrom := ecdsa.NewKey(deltaShareFrom, deltaShareFrom.Act(deltaShareFrom.Curve().NewBasePoint()), deltaShareFrom.Curve())
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

	koptsFrom, err := keyopts.NewOptions().Set("id", r.cfg.KeyID(), "partyid", string(from))
	if err != nil {
		return errors.WithMessage(err, "sign.round4.StoreBroadcastMessage: failed to create options")
	}

	koptsTo, err := keyopts.NewOptions().Set("id", r.cfg.KeyID(), "partyid", string(to))
	if err != nil {
		return errors.WithMessage(err, "sign.round4.StoreBroadcastMessage: failed to create options")
	}

	soptsFrom, err := keyopts.NewOptions().Set("id", r.cfg.ID(), "partyid", string(from))
	if err != nil {
		return errors.WithMessage(err, "sign.round4.StoreBroadcastMessage: failed to create options")
	}

	soptsRoot, err := keyopts.NewOptions().Set("id", r.cfg.ID(), "partyid", string("ROOT"))
	if err != nil {
		return errors.WithMessage(err, "sign.round4.StoreBroadcastMessage: failed to create options")
	}

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

	sopts, err := keyopts.NewOptions().Set("id", r.cfg.ID(), "partyid", string(r.SelfID()))
	if err != nil {
		return nil, errors.WithMessage(err, "sign.round4.StoreBroadcastMessage: failed to create options")
	}

	soptsRoot, err := keyopts.NewOptions().Set("id", r.cfg.ID(), "partyid", "ROOT")
	if err != nil {
		return nil, errors.WithMessage(err, "sign.round4.StoreBroadcastMessage: failed to create options")
	}

	// δ = ∑ⱼ δⱼ
	deltaSharesOpts := make([]com_keyopts.Options, 0)
	for _, j := range r.OtherPartyIDs() {
		soptsj, err := keyopts.NewOptions().Set("id", r.cfg.ID(), "partyid", string(j))
		if err != nil {
			return nil, errors.WithMessage(err, "sign.round4.StoreBroadcastMessage: failed to create options")
		}
		deltaSharesOpts = append(deltaSharesOpts, soptsj)
	}
	Delta, err := r.delta.SumKeys(deltaSharesOpts...)
	if err != nil {
		return nil, err
	}

	// Δ = ∑ⱼ Δⱼ
	BigDelta := r.Group().NewPoint()
	for _, j := range r.PartyIDs() {
		soptsj, err := keyopts.NewOptions().Set("id", r.cfg.ID(), "partyid", string(j))
		if err != nil {
			return nil, errors.WithMessage(err, "sign.round4.StoreBroadcastMessage: failed to create options")
		}
		bigDeltaj, err := r.bigDelta.GetKey(soptsj)
		if err != nil {
			return nil, err
		}
		BigDelta = BigDelta.Add(bigDeltaj.PublicKeyRaw())
	}

	// Δ == [δ]G
	if !BigDelta.Equal(Delta.PublicKeyRaw()) {
		return r.AbortRound(errors.New("computed Δ is inconsistent with [δ]G")), nil
	}

	// R = [δ⁻¹] Γ
	gamma, err := r.gamma.GetKey(soptsRoot)
	if err != nil {
		return nil, err
	}
	BigR := Delta.Act(gamma.PublicKeyRaw(), true) // δ⁻¹
	R := BigR.XScalar()                           // r = R|ₓ

	// rχᵢ
	RChi, err := r.chi.Mul(R, sopts)
	if err != nil {
		return nil, err
	}

	// km = Hash(m)⋅kᵢ
	// σᵢ = rχᵢ + kᵢm
	m := curve.FromHash(r.Group(), r.cfg.Message())
	SigmaShare, err := r.signK.Commit(m, RChi, sopts)
	if err != nil {
		return nil, err
	}
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
		Helper:      r.Helper,
		cfg:         r.cfg,
		statemgr:    r.statemgr,
		msgmgr:      r.msgmgr,
		bcstmgr:     r.bcstmgr,
		hash_mgr:    r.hash_mgr,
		paillier_km: r.paillier_km,
		pedersen_km: r.pedersen_km,
		ec:          r.ec,
		vss_mgr:     r.vss_mgr,
		gamma:       r.gamma,
		signK:       r.signK,
		delta:       r.delta,
		chi:         r.chi,
		bigDelta:    r.bigDelta,
		gamma_pek:   r.gamma_pek,
		signK_pek:   r.signK_pek,
		delta_mta:   r.delta_mta,
		chi_mta:     r.chi_mta,
		sigma:       r.sigma,
		signature:   r.signature,
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
