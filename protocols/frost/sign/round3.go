package sign

import (
	"fmt"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/config"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/state"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/message"
	result "github.com/mr-shifu/mpc-lib/pkg/mpc/result/eddsa"
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
	rootOpts.Set("id", r.ID)

	// 1. Reproduce c random number as commitment to the nonce
	rootSig, err := r.sigmgr.Get(rootOpts)
	if err != nil {
		return err
	}
	ecKey, err := r.ecdsa_km.GetKey(kopts)
	if err != nil {
		return err
	}
	cHash := hash.New(nil)
	_ = cHash.WriteAny(rootSig.R(), ecKey.PublicKeyRaw(), r.cfg.Message())
	c := sample.Scalar(cHash.Digest(), r.Group())

	// 2. Verify the z_i response
	fromSig, err := r.sigmgr.Get(sopts)
	if err != nil {
		return err
	}
	expected := c.Act(ecKey.PublicKeyRaw()).Add(fromSig.R())
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

// RoundNumber implements round.Content.
func (broadcast3) RoundNumber() round.Number { return 3 }
