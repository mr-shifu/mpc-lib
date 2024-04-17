package keygen

import (
	"fmt"

	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/commitment"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/rid"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/vss"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/config"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/message"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/state"
)

var _ round.Round = (*round1)(nil)

type round1 struct {
	*round.Helper

	configmgr   config.KeyConfigManager
	statemgr    state.MPCStateManager
	msgmgr      message.MessageManager
	bcstmgr     message.MessageManager
	ec_km       ecdsa.ECDSAKeyManager
	ec_vss_km   ecdsa.ECDSAKeyManager
	vss_mgr     vss.VssKeyManager
	chainKey_km rid.RIDManager
	commit_mgr  commitment.CommitmentManager
}

// VerifyMessage implements round.Round.
func (r *round1) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (r *round1) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
func (r *round1) Finalize(out chan<- *round.Message) (round.Session, error) {
	// ToDo maybe we can include create options into helper
	opts := keyopts.Options{}
	opts.Set("id", r.ID, "partyid", string(r.SelfID()))

	// 1, Generate a new EC Key Pair
	k, err := r.ec_km.GenerateKey(opts)
	if err != nil {
		return r, fmt.Errorf("frost.Keygen.Round1: failed to generate EC key pair")
	}

	// ToDo maybe we'd better to return vss instance by Generate function
	// 2. Generate a new VSS share with EC Private Key as polynomial constant
	if err := k.GenerateVSSSecrets(r.Threshold(), opts); err != nil {
		return r, fmt.Errorf("frost.Keygen.Round1: failed to generate VSS secrets")
	}
	vss, err := k.VSS(opts)
	if err != nil {
		return r, fmt.Errorf("frost.Keygen.Round1: failed to get VSS")
	}
	exp, err := vss.ExponentsRaw()
	if err != nil {
		return r, fmt.Errorf("frost.Keygen.Round1: failed to get VSS exponents")
	}

	// ToDo maybe we can combine commit and proof generation into a single function
	// 3. Generate a Schnorr proof of knowledge for the EC Private Key
	sch_cmt, err := k.NewSchnorrCommitment()
	if err != nil {
		return r, fmt.Errorf("frost.Keygen.Round1: failed to generate Schnorr commitment")
	}
	sch_proof, err := k.GenerateSchnorrProof(r.Helper.HashForID(r.SelfID()))
	if err != nil {
		return r, fmt.Errorf("frost.Keygen.Round1: failed to generate Schnorr proof")
	}

	// 4. Generate a new RID for the chaining key
	chainKey, err := r.chainKey_km.GenerateKey(opts)
	if err != nil {
		return r, fmt.Errorf("frost.Keygen.Round1: failed to generate RID")
	}

	// ToDo maybe we can commbine Commit generation into commit manager
	// 5. Generate commitment from chainKey and import them to the commitment store
	cmt, dcmt, err := r.HashForID(r.SelfID()).Commit(chainKey)
	if err != nil {
		return r, fmt.Errorf("failed to commit to chain key")
	}
	commitment := r.commit_mgr.NewCommitment(cmt, dcmt)
	if err := r.commit_mgr.Import(commitment, opts); err != nil {
		return r, err
	}

	// 6. Broadcast public data
	err = r.BroadcastMessage(out, &broadcast2{
		VSSPolynomial:     exp,
		SchnorrCommitment: sch_cmt,
		SchnorrProof:      sch_proof,
		Commitment:        cmt,
	})
	if err != nil {
		return r, err
	}

	// update last round processed in StateManager
	if err := r.statemgr.SetLastRound(r.ID, int(r.Number())); err != nil {
		return r, err
	}

	return &round2{
		Helper:      r.Helper,
		configmgr:   r.configmgr,
		statemgr:    r.statemgr,
		msgmgr:      r.msgmgr,
		bcstmgr:     r.bcstmgr,
		ec_km:       r.ec_km,
		ec_vss_km:   r.ec_vss_km,
		vss_mgr:     r.vss_mgr,
		chainKey_km: r.chainKey_km,
		commit_mgr:  r.commit_mgr,
	}, nil
}

func (r *round1) CanFinalize() bool {
	return true
}

// PreviousRound implements round.Round.
func (round1) PreviousRound() round.Round { return nil }

// MessageContent implements round.Round.
func (round1) MessageContent() round.Content { return nil }

// Number implements round.Round.
func (round1) Number() round.Number { return 1 }
