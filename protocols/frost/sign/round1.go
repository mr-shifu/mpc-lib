package sign

import (
	"crypto/rand"

	"github.com/mr-shifu/mpc-lib/core/math/sample"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/vss"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/config"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/message"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/result"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/state"
	"github.com/zeebo/blake3"
)

// This round sort of corresponds with Figure 2 of the Frost paper:
//
//	https://eprint.iacr.org/2020/852.pdf
//
// The main difference is that instead of having a separate pre-processing step,
// we instead have an additional round at the start of the signing step.
// The goal of this round is to generate two nonces, and corresponding commitments.
//
// There are also differences corresponding to the lack of a signing authority,
// namely that these commitments are broadcast, instead of stored with the authority.
type round1 struct {
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

// VerifyMessage implements round.Round.
func (r *round1) VerifyMessage(round.Message) error         { return nil }
func (r *round1) StoreBroadcastMessage(round.Message) error { return nil }
func (r *round1) StoreMessage(round.Message) error          { return nil }

const deriveHashKeyContext = "Derive hash Key"

// Finalize implements round.Round.
func (r *round1) Finalize(out chan<- *round.Message) (round.Session, error) {
	opts := keyopts.Options{}
	opts.Set("id", r.ID, "partyid", string(r.SelfID()))

	kopts := keyopts.Options{}
	kopts.Set("id", r.cfg.KeyID(), "partyid", string(r.SelfID()))

	k, err := r.ecdsa_km.GetKey(kopts)
	if err != nil {
		return r, err
	}
	kb, err := k.Bytes()
	if err != nil {
		return r, err
	}

	// ToDo we may move this to utils package
	hashKey := make([]byte, 32)
	blake3.DeriveKey(deriveHashKeyContext, kb, hashKey)
	nonceHasher, _ := blake3.NewKeyed(hashKey)
	_, _ = nonceHasher.Write(r.Hash().Sum())
	_, _ = nonceHasher.Write(r.cfg.Message())
	a := make([]byte, 32)
	_, _ = rand.Read(a)
	_, _ = nonceHasher.Write(a)
	nonceDigest := nonceHasher.Digest()

	// Generate random (d, D) pair param and import them into EC keystore
	d := sample.ScalarUnit(nonceDigest, r.Group())
	D := d.ActOnBase()
	sign_d := r.sign_d.NewKey(d, D, r.Group())
	r.sign_d.ImportKey(sign_d, opts)

	// Generate random (e, E) pair param and import them into EC keystore
	e := sample.ScalarUnit(nonceDigest, r.Group())
	E := e.ActOnBase()
	sign_e := r.sign_e.NewKey(e, E, r.Group())
	r.sign_e.ImportKey(sign_e, opts)

	// Broadcast the commitments
	err = r.BroadcastMessage(out, &broadcast2{
		D: D,
		E: E,
	})
	if err != nil {
		return r, err
	}

	// update last round processed in StateManager
	if err := r.statemgr.SetLastRound(r.ID, int(r.Number())); err != nil {
		return r, err
	}

	return &round2{
		cfg:        r.cfg,
		statemgr:   r.statemgr,
		sigmgr:     r.sigmgr,
		msgmgr:     r.msgmgr,
		bcstmgr:    r.bcstmgr,
		ecdsa_km:   r.ecdsa_km,
		ec_vss_km:  r.ec_vss_km,
		ec_sign_km: r.ec_sign_km,
		vss_mgr:    r.vss_mgr,
		sign_d:     r.sign_d,
		sign_e:     r.sign_e,
		hash_mgr:   r.hash_mgr,
		Helper:     r.Helper,
	}, nil
}

func (round1) CanFinalize() bool { return true }

// MessageContent implements round.Round.
func (round1) MessageContent() round.Content { return nil }

// Number implements round.Round.
func (round1) Number() round.Number { return 1 }
