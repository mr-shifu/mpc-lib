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
	com_keyopts "github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/config"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/message"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/state"
)

type broadcast3 struct {
	round.NormalBroadcastContent

	ChainKey     types.RID
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
	fromOpts.Set("id", r.ID, "partyid", string(from))

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
	if !r.HashForID(from).Decommit(
		cmt.Commitment(),
		body.Decommitment,
		[]byte(body.ChainKey),
	) {
		return errors.New("failed to decommit")
	}

	// 3. Import the decommitment
	if err := r.commit_mgr.ImportDecommitment(body.Decommitment, fromOpts); err != nil {
		return err
	}

	// 5. Import the chainKey
	if _, err := r.chainKey_km.ImportKey(body.ChainKey, fromOpts); err != nil {
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
	fromOpts.Set("id", r.ID, "partyid", string(from))

	// 1. Verify VSS share against exponents evaluation
	expected := body.VSSShare.ActOnBase()
	actual, err := r.vss_mgr.EvaluateByExponents(r.SelfID().Scalar(r.Group()), fromOpts)
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
	vssOpts.Set("id", hex.EncodeToString(vss.SKI()), "partyid", string(from))
	ec_vss := r.ec_vss_km.NewKey(body.VSSShare, expected, r.Group())
	if _, err := r.ec_vss_km.ImportKey(ec_vss, vssOpts); err != nil {
		return err
	}

	// Mark the message as received
	if err := r.msgmgr.Import(
		r.msgmgr.NewMessage(r.ID, int(r.Number()), string(msg.From), true),
	); err != nil {
		return err
	}

	return nil
}

// Finalize implements round.Round.
func (r *round3) Finalize(chan<- *round.Message) (round.Session, error) {
	// Verify if all parties commitments are received
	if !r.CanFinalize() {
		return nil, round.ErrNotEnoughMessages
	}

	rootOpts := keyopts.Options{}
	rootOpts.Set("id", r.ID, "partyid", "ROOT")

	opts := keyopts.Options{}
	opts.Set("id", r.ID, "partyid", string(r.SelfID()))

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

	// 2. Sum all VSS Exponents Shares to generate MPC VSS Exponent and Import it to VSS Keystore
	vssOptsList := make([]com_keyopts.Options, 0)
	for _, partyID := range r.PartyIDs() {
		partyOpts := keyopts.Options{}
		partyOpts.Set("id", r.ID, "partyid", string(partyID))
		vssOptsList = append(vssOptsList, partyOpts)
	}
	rootVss, err := r.vss_mgr.SumExponents(vssOptsList...)
	if err != nil {
		return nil, err
	}
	vssPoly, err := r.vss_mgr.ImportSecrets(rootVss, rootOpts)
	if err != nil {
		return nil, err
	}

	// 3. calculate the group public key from group VSS Exponents and import it to ECDSA Keystore
	exponents, err := vssPoly.ExponentsRaw()
	if err != nil {
		return nil, err
	}
	pubKey := exponents.Constant()
	key := r.ec_km.NewKey(nil, pubKey, r.Group())
	if _, err := r.ec_km.ImportKey(key, rootOpts); err != nil {
		return nil, err
	}

	return r.ResultRound(&Config{
		ID:        r.SelfID(),
		Threshold: r.Threshold(),
		PublicKey: pubKey,
	}), nil
}

func (r *round3) CanFinalize() bool {
	// Verify if all parties commitments are received
	var parties []string
	for _, p := range r.OtherPartyIDs() {
		parties = append(parties, string(p))
	}
	bcstsRcvd, err := r.bcstmgr.HasAll(r.ID, int(r.Number()), parties)
	if err != nil {
		return false
	}
	msgssRcvd, err := r.msgmgr.HasAll(r.ID, int(r.Number()), parties)
	if err != nil {
		return false
	}
	return bcstsRcvd && msgssRcvd
}

// BroadcastContent implements round.BroadcastRound.
func (r *round3) BroadcastContent() round.BroadcastContent {
	return &broadcast3{}
}

// MessageContent implements round.Round.
func (r *round3) MessageContent() round.Content {
	return &message3{
		VSSShare: r.Group().NewScalar(),
	}
}

// Number implements round.Round.
func (round3) Number() round.Number { return 3 }

// RoundNumber implements round.Content.
func (broadcast3) RoundNumber() round.Number { return 3 }

// RoundNumber implements round.Content.
func (message3) RoundNumber() round.Number { return 3 }
