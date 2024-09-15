package sign

import (
	core_ecdsa "github.com/mr-shifu/mpc-lib/core/ecdsa"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/lib/round"
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

var _ round.Round = (*round5)(nil)

type round5 struct {
	*round.Helper

	cfg      config.SignConfig
	statemgr state.MPCStateManager
	sigmgr   result.EcdsaSignatureManager
	msgmgr   message.MessageManager
	bcstmgr  message.MessageManager

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

	soptsFrom, err := keyopts.NewOptions().Set("id", r.cfg.ID(), "partyid", string(msg.From))
	if err != nil {
		return errors.WithMessage(err, "sign.round5.StoreBroadcastMessage: failed to create options")
	}

	// r.SigmaShares[msg.From] = body.SigmaShare
	if err := r.sigmgr.SetSigma(body.SigmaShare, soptsFrom); err != nil {
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

	soptsRoot, err := keyopts.NewOptions().Set("id", r.cfg.ID(), "partyid", string("ROOT"))
	if err != nil {
		return nil, errors.WithMessage(err, "sign.round5.StoreBroadcastMessage: failed to create options")
	}

	koptsRoot, err := keyopts.NewOptions().Set("id", r.cfg.KeyID(), "partyid", string("ROOT"))
	if err != nil {
		return nil, errors.WithMessage(err, "sign.round5.StoreBroadcastMessage: failed to create options")
	}

	// compute σ = ∑ⱼ σⱼ
	Sigma := r.Group().NewScalar()
	for _, j := range r.PartyIDs() {
		soptsj, err := keyopts.NewOptions().Set("id", r.cfg.ID(), "partyid", string(j))
		if err != nil {
			return nil, errors.WithMessage(err, "sign.round5.StoreBroadcastMessage: failed to create options")
		}
		sig, err := r.sigmgr.Get(soptsj)
		if err != nil {
			return nil, err
		}
		Sigma = Sigma.Add(sig.SignSigma())
	}

	if err := r.sigmgr.SetSigma(Sigma, soptsRoot); err != nil {
		return nil, err
	}
	sig, err := r.sigmgr.Get(soptsRoot)
	if err != nil {
		return nil, err
	}

	signature := &core_ecdsa.Signature{
		R: sig.SignR(),
		S: sig.SignSigma(),
	}

	ecKey, err := r.ec.GetKey(soptsRoot)
	if err != nil {
		return nil, err
	}
	if !signature.Verify(ecKey.PublicKeyRaw(), r.cfg.Message()) {
		// update state to Aborted in StateManager
		if err := r.statemgr.SetAborted(r.ID, true); err != nil {
			return r, err
		}
		return r.AbortRound(errors.New("failed to validate signature")), nil
	}

	ecKey, err = r.ec.GetKey(koptsRoot)
	if err != nil {
		return nil, err
	}
	if !signature.Verify(ecKey.PublicKeyRaw(), r.cfg.Message()) {
		// update state to Aborted in StateManager
		if err := r.statemgr.SetAborted(r.ID, true); err != nil {
			return r, err
		}
		return r.AbortRound(errors.New("failed to validate signature")), nil
	}

	// update last round processed in StateManager
	if err := r.statemgr.SetLastRound(r.ID, int(r.Number())); err != nil {
		return r, err
	}
	// update state to Completed in StateManager
	if err := r.statemgr.SetCompleted(r.ID, true); err != nil {
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
