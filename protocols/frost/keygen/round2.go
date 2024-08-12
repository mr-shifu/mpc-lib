package keygen

import (
	"filippo.io/edwards25519"
	"github.com/mr-shifu/mpc-lib/core/hash"
	"github.com/mr-shifu/mpc-lib/core/math/polynomial-ed25519"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/rid"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/commitment"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ed25519"
	vssed25519 "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss-ed25519"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/config"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/message"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/state"
	"github.com/pkg/errors"
)

type broadcast2 struct {
	round.ReliableBroadcastContent
	VSSPolynomial *polynomial.Polynomial

	SchnorrProof []byte

	Commitment hash.Commitment
}

type round2 struct {
	*round.Helper

	configmgr   config.KeyConfigManager
	statemgr    state.MPCStateManager
	msgmgr      message.MessageManager
	bcstmgr     message.MessageManager
	ed_km       ed25519.Ed25519KeyManager
	ed_vss_km   ed25519.Ed25519KeyManager
	vss_mgr     vssed25519.VssKeyManager
	chainKey_km rid.RIDManager
	commit_mgr  commitment.CommitmentManager
}

// StoreBroadcastMessage implements round.BroadcastRound.
func (r *round2) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcast2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if body.VSSPolynomial == nil {
		return errors.New("frost.Keygen.Round2: invalid VSS polynomial")
	}

	state, err := r.statemgr.Get(r.ID)
	if err != nil {
		return errors.WithMessage(err, "fromst.Keygen.Round2: failed to retreive key state")
	}
	refresh := state.Refresh()

	fromOpts, err := keyopts.NewOptions().Set("id", r.ID, "partyid", string(from))
	if err != nil {
		return errors.New("frost.Keygen.Round2: failed to create options")
	}
	fromRefreshOpts, err := keyopts.NewOptions().Set("id", "refresh-"+r.ID, "partyid", string(from))
	if err != nil {
		return errors.New("frost.Keygen.Round2: failed to create options")
	}

	// validate commitment and import it to commitment store
	if err := body.Commitment.Validate(); err != nil {
		return errors.WithMessage(err, "frost.Keygen.Round2: invalid commitment")
	}
	cmt := r.commit_mgr.NewCommitment(body.Commitment, nil)
	// if !refresh {
	if err := r.commit_mgr.Import(cmt, fromOpts); err != nil {
		return errors.WithMessage(err, "frost.Keygen.Round2: failed to import commitment")
	}

	// ToDo we must be able to first verify schnorr proof before importing commitment
	// Import Party Public Key and VSS Exponents
	if !refresh {
		pk := body.VSSPolynomial.Constant()
		k, err := ed25519.NewKey(nil, pk)
		if err != nil {
			return err
		}
		_, err = r.ed_km.ImportKey(k, fromOpts)
		if err != nil {
			return err
		}
	} else {
		if eq := edwards25519.NewIdentityPoint().Equal(body.VSSPolynomial.Constant()); eq != 1 {
			return errors.New("frost.Keygen.Round2: Invalid VSS Polynomials")
		}
	}

	// ToDo it's better to verify proof without importing commitment
	// verify schnorr proof
	if !refresh {
		if err := r.ed_km.ImportSchnorrProof(body.SchnorrProof, fromOpts); err != nil {
			return err
		}
		verified, err := r.ed_km.VerifySchnorrProof(r.Helper.HashForID(from), fromOpts)
		if err != nil {
			return err
		}
		if !verified {
			return errors.New("frost.Keygen.Round2: schnorr proof verification failed")
		}
	}

	// Import VSS Polynomial
	vssKey := vssed25519.NewVssKey(body.VSSPolynomial)
	if !refresh {
		if _, err := r.vss_mgr.ImportSecrets(vssKey, fromOpts); err != nil {
			return err
		}
	} else {
		if _, err := r.vss_mgr.ImportSecrets(vssKey, fromRefreshOpts); err != nil {
			return err
		}
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

func (r *round2) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Verify if all parties commitments are received
	if !r.CanFinalize() {
		return nil, round.ErrNotEnoughMessages
	}

	state, err := r.statemgr.Get(r.ID)
	if err != nil {
		return nil, errors.WithMessage(err, "fromst.Keygen.Round2: failed to retreive key state")
	}
	refresh := state.Refresh()

	opts, err := keyopts.NewOptions().Set("id", r.ID, "partyid", string(r.SelfID()))
	if err != nil {
		return nil, errors.New("frost.Keygen.Round2: failed to create options")
	}
	refreshOpts, err := keyopts.NewOptions().Set("id", "refresh-"+r.ID, "partyid", string(r.SelfID()))
	if err != nil {
		return nil, errors.New("frost.Keygen.Round2: failed to create options")
	}

	// 1. Get ChainKey from commitment store
	var chainKey rid.RID
	if !refresh {
		chainKey, err = r.chainKey_km.GetKey(opts)
		if err != nil {
			return r, err
		}
	} else {
		chainKey, err = r.chainKey_km.GetKey(refreshOpts)
		if err != nil {
			return r, err
		}
	}

	// 2. Get Decommitment generated for chainKey by round1
	// var cmt commitment.Commitment
	// if !refresh {
	cmt, err := r.commit_mgr.Get(opts)
	if err != nil {
		return r, err
	}

	if err := r.BroadcastMessage(out, &broadcast3{
		ChainKey:     chainKey.Raw(),
		Decommitment: cmt.Decommitment(),
	}); err != nil {
		return r, err
	}

	// 3. Evaluate VSS Polynomial for all parties
	var vssKey vssed25519.VssKey
	if !refresh {
		vssKey, err = r.vss_mgr.GetSecrets(opts)
		if err != nil {
			return r, err
		}
	} else {
		vssKey, err = r.vss_mgr.GetSecrets(refreshOpts)
		if err != nil {
			return r, err
		}
	}
	for _, j := range r.PartyIDs() {
		jScalar, err := j.Ed25519Scalar()
		if err != nil {
			return nil, err
		}
		share, err := vssKey.Evaluate(jScalar)
		if err != nil {
			return r, err
		}
		if j != r.SelfID() {
			err := r.SendMessage(out, &message3{
				VSSShare: share,
			}, j)
			if err != nil {
				return r, err
			}
		} else {
			// Import Self Share to the keystore
			sharePublic := new(edwards25519.Point).ScalarBaseMult(share)
			shareKey, err := ed25519.NewKey(share, sharePublic)
			if err != nil {
				return nil, err
			}

			kid := r.ID
			if refresh {
				kid = "refresh-" + r.ID
			}
			vssOpts, err := keyopts.NewOptions().Set("id", kid, "partyid", string(r.SelfID()))
			if err != nil {
				return nil, errors.New("frost.Keygen.Round2: failed to create options")
			}
			if _, err := r.ed_vss_km.ImportKey(shareKey, vssOpts); err != nil {
				return nil, err
			}
		}
	}

	// update last round processed in StateManager
	if err := r.statemgr.SetLastRound(r.ID, int(r.Number())); err != nil {
		return r, err
	}

	return &round3{
		Helper:      r.Helper,
		configmgr:   r.configmgr,
		statemgr:    r.statemgr,
		msgmgr:      r.msgmgr,
		bcstmgr:     r.bcstmgr,
		ed_km:       r.ed_km,
		ed_vss_km:   r.ed_vss_km,
		vss_mgr:     r.vss_mgr,
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

// BroadcastContent implements round.BroadcastRound.
func (r *round2) BroadcastContent() round.BroadcastContent {
	return &broadcast2{
		VSSPolynomial: new(polynomial.Polynomial),
		// SchnorrProof:  r.Group().NewScalar(),
	}
}

// MessageContent implements round.Round.
func (round2) MessageContent() round.Content { return nil }

// Number implements round.Round.
func (round2) Number() round.Number { return 2 }

// RoundNumber implements round.Content.
func (broadcast2) RoundNumber() round.Number { return 2 }
