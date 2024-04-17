package keygen

import (
	"encoding/hex"
	"errors"

	"github.com/mr-shifu/mpc-lib/core/hash"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/lib/types"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/commitment"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/rid"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/vss"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/config"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/message"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/state"
)

type broadcast3 struct {
	ChainKey     rid.RID
	Decommitment hash.Decommitment
}

type message3 struct {
	VSSShare curve.Scalar
}

type round3 struct {
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

// StoreBroadcastMessage implements round.BroadcastRound.
func (r *round3) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcast3)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	fromOpts := keyopts.Options{}
	fromOpts.Set("id", r.ID, "partyid", from)

	// 1. Validate ChainKey and Decommitment
	if err := body.ChainKey.Validate(); err != nil {
		return err
	}
	if err := body.Decommitment.Validate(); err != nil {
		return err
	}

	// ToDo Decommit() can be embedded in commit manager
	// 2. Verify the decommitment against chainKey
	cmt, err := r.commit_mgr.Get(fromOpts)
	if err != nil {
		return err
	}
	if !r.Hash().Clone().Decommit(
		cmt.Commitment(),
		body.Decommitment,
		body.ChainKey,
	) {
		return errors.New("failed to decommit")
	}

	// 3. Import the decommitment
	if err := r.commit_mgr.ImportDecommitment(body.Decommitment, fromOpts); err != nil {
		return err
	}

	// 5. Import the chainKey
	if _, err := r.chainKey_km.ImportKey(body.ChainKey.Raw(), fromOpts); err != nil {
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
func (r *round3) VerifyMessage(msg round.Message) error {
	body, ok := msg.Content.(*message3)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	// check nil
	if body.VSSShare == nil {
		return round.ErrNilFields
	}

	return nil
}

// StoreMessage implements round.Round.
//
// Verify the VSS condition here since we will not be sending this message to other parties for verification.
func (r *round3) StoreMessage(msg round.Message) error {
	from, body := msg.From, msg.Content.(*message3)

	// These steps come from Figure 1, Round 2 of the Frost paper

	// 2. "Each Pᵢ verifies their shares by calculating
	//
	//   fₗ(i) * G =? ∑ₖ₌₀ᵗ (iᵏ mod q) * ϕₗₖ
	//
	// aborting if the check fails."
	fromOpts := keyopts.Options{}
	fromOpts.Set("id", r.ID, "partyid", from)

	// 1. Verify VSS share against exponents evaluation
	expected := body.VSSShare.ActOnBase()
	actual, err := r.vss_mgr.EvaluateByExponents(from.Scalar(r.Group()), fromOpts)
	if err != nil {
		return err
	}
	if !expected.Equal(actual) {
		return errors.New("vss share verification failed")
	}

	// 2. Import the VSS share as an EC key
	vss, err := r.vss_mgr.GetSecrets(fromOpts)
	if err != nil {
		return err
	}
	vssOpts := keyopts.Options{}
	vssOpts.Set("id", hex.EncodeToString(vss.SKI()), "partyid", from)
	ec_vss := r.ec_vss_km.NewKey(body.VSSShare, expected, r.Group())
	if _, err := r.ec_vss_km.ImportKey(ec_vss, vssOpts); err != nil {
		return err
	}

	return nil
}

// Finalize implements round.Round.
func (r *round3) Finalize(chan<- *round.Message) (round.Session, error) {
	rootOpts := keyopts.Options{}
	rootOpts.Set("id", r.ID, "partyid", "ROOT")

	// 1. XOR all chainKeys to get the group chainKey
	chainKey := types.EmptyRID()
	for _, j := range r.PartyIDs() {
		partyOpts := keyopts.Options{}
		partyOpts.Set("id", r.ID, "partyid", string(j))
		ck, err := r.chainKey_km.GetKey(partyOpts)
		if err != nil {
			return nil, err
		}
		chainKey.XOR(ck.Raw())
	}
	if _, err := r.chainKey_km.ImportKey(chainKey, rootOpts); err != nil {
		return nil, err
	}

	return nil, nil
}

// Number implements round.Round.
func (round3) Number() round.Number { return 2 }

// RoundNumber implements round.Content.
func (broadcast3) RoundNumber() round.Number { return 3 }

// RoundNumber implements round.Content.
func (message3) RoundNumber() round.Number { return 3 }
