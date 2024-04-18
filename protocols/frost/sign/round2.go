package sign

import (
	"fmt"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/config"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/state"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/message"
)

// This round roughly corresponds with steps 3-6 of Figure 3 in the Frost paper:
//
//	https://eprint.iacr.org/2020/852.pdf
//
// The main differences stem from the lack of a signature authority.
//
// This means that instead of receiving a bundle of all the commitments, instead
// each participant sends us their commitment directly.
//
// Then, instead of sending our scalar response to the authority, we broadcast it
// to everyone instead.
type round2 struct {
	*round.Helper
	cfg        config.SignConfig
	statemgr   state.MPCStateManager
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

type broadcast2 struct {
	round.ReliableBroadcastContent
	// D_i is the first commitment produced by the sender of this message.
	D curve.Point
	// E_i is the second commitment produced by the sender of this message.
	E curve.Point
}

// StoreBroadcastMessage implements round.BroadcastRound.
func (r *round2) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*broadcast2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	
	if body.D.IsIdentity() || body.E.IsIdentity() {
		return fmt.Errorf("nonce commitment is the identity point")
	}

	opts := keyopts.Options{}
	opts.Set("id", r.ID, "partyid", string(msg.From))

	// store D params as EC Key into EC keystore
	dk := r.sign_d.NewKey(nil, body.D, r.Group())
	if _, err := r.sign_d.ImportKey(dk, opts); err != nil {
		return err
	}

	// store E params as EC Key into EC keystore
	ek := r.sign_e.NewKey(nil, body.E, r.Group())
	if _, err := r.sign_e.ImportKey(ek, opts); err != nil {
		return err
	}

	return nil
}

// VerifyMessage implements round.Round.
func (round2) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (round2) StoreMessage(round.Message) error { return nil }

// MessageContent implements round.Round.
func (round2) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcast2) RoundNumber() round.Number { return 2 }

// BroadcastContent implements round.BroadcastRound.
func (r *round2) BroadcastContent() round.BroadcastContent {
	return &broadcast2{
		D: r.Group().NewPoint(),
		E: r.Group().NewPoint(),
	}
}

// Number implements round.Round.
func (round2) Number() round.Number { return 2 }
