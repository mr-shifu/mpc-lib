package sign

import (
	"fmt"

	"github.com/mr-shifu/mpc-lib/core/eddsa"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/vss"
	sw_hash "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/config"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/message"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/result"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/state"
)

type broadcast3 struct {
	round.NormalBroadcastContent
	// Z_i is the response scalar computed by the sender of this message.
	Z curve.Scalar
}

type round3 struct {
	*round.Helper
	cfg        config.SignConfig
	statemgr   state.MPCStateManager
	sigmgr     result.EddsaSignatureManager
	msgmgr     message.MessageManager
	bcstmgr    message.MessageManager
	ecdsa_km   ecdsa.ECDSAKeyManager
	ec_vss_km  ecdsa.ECDSAKeyManager
	ec_sign_km ecdsa.ECDSAKeyManager
	vss_mgr    vss.VssKeyManager
	sign_d     ecdsa.ECDSAKeyManager
	sign_e     ecdsa.ECDSAKeyManager
	hash_mgr   hash.HashManager
}

// StoreBroadcastMessage implements round.BroadcastRound.
func (r *round3) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcast3)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	// check nil
	if body.Z == nil {
		return round.ErrNilFields
	}

	kopts := keyopts.Options{}
	kopts.Set("id", r.cfg.KeyID(), "partyid", string(msg.From))

	sopts := keyopts.Options{}
	sopts.Set("id", r.ID, "partyid", string(msg.From))

	rootOpts := keyopts.Options{}
	rootOpts.Set("id", r.ID, "partyid", "ROOT")

	// 1. Reproduce c random number as commitment to the nonce
	rootSig, err := r.sigmgr.Get(rootOpts)
	if err != nil {
		return err
	}
	ecKey, err := r.ecdsa_km.GetKey(kopts)
	if err != nil {
		return err
	}
	cHash := sw_hash.New(nil)
	_ = cHash.WriteAny(rootSig.R(), ecKey.PublicKeyRaw(), r.cfg.Message())
	c := sample.Scalar(cHash.Digest(), r.Group())

	// 2. Verify the z_i response
	signKey, err := r.ec_sign_km.GetKey(sopts)
	if err != nil {
		return err
	}
	fromSig, err := r.sigmgr.Get(sopts)
	if err != nil {
		return err
	}
	expected := c.Act(signKey.PublicKeyRaw()).Add(fromSig.R())
	actual := body.Z.ActOnBase()
	if !actual.Equal(expected) {
		return fmt.Errorf("failed to verify response from %v", from)
	}

	// Import z_i into the signature reposnse share
	if err := r.sigmgr.SetZ(body.Z, sopts); err != nil {
		return err
	}

	return nil
}

// VerifyMessage implements round.Round.
func (round3) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (round3) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round.
func (r *round3) Finalize(chan<- *round.Message) (round.Session, error) {
	// 1. Compute the group's response z = ∑ᵢ zᵢ
	z := r.Group().NewScalar()
	for _, l := range r.PartyIDs() {
		opts := keyopts.Options{}
		opts.Set("id", r.ID, "partyid", string(l))
		sig, err := r.sigmgr.Get(opts)
		if err != nil {
			return r.AbortRound(err), nil
		}
		z.Add(sig.Z())
	}
	rootOpts := keyopts.Options{}
	rootOpts.Set("id", r.ID, "partyid", "ROOT")
	if err := r.sigmgr.SetZ(z, rootOpts); err != nil {
		return r, nil
	}

	// 2. Verify the signature
	ecKey, err := r.ecdsa_km.GetKey(keyopts.Options{"id": r.cfg.KeyID(), "partyid": string(r.SelfID())})
	if err != nil {
		return r.AbortRound(err), nil
	}
	s, err := r.sigmgr.Get(rootOpts)
	if err != nil {
		return r.AbortRound(err), nil
	}
	sig := eddsa.Signature{
		R: s.R(),
		Z: z,
	}
	if eddsa.Verify(ecKey.PublicKeyRaw(), sig, r.cfg.Message()); err != nil {
		return r.AbortRound(fmt.Errorf("generated signature failed to verify")), nil
	}

	return r.ResultRound(s), nil
}

func (r *round3) CanFinalize() bool {
	return true
}

// MessageContent implements round.Round.
func (round3) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcast3) RoundNumber() round.Number { return 3 }

// BroadcastContent implements round.BroadcastRound.
func (r *round3) BroadcastContent() round.BroadcastContent {
	return &broadcast3{
		Z: r.Group().NewScalar(),
	}
}

// Number implements round.Round.
func (round3) Number() round.Number { return 3 }
