package sign

import (
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

var _ round.Round = (*round1)(nil)

type round1 struct {
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

// StoreBroadcastMessage implements round.Round.
func (r *round1) StoreBroadcastMessage(round.Message) error { return nil }

// VerifyMessage implements round.Round.
func (round1) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (round1) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
//
// - sample kᵢ, γᵢ <- 𝔽,
// - Γᵢ = [γᵢ]⋅G
// - Gᵢ = Encᵢ(γᵢ;νᵢ)
// - Kᵢ = Encᵢ(kᵢ;ρᵢ)
//
// NOTE
// The protocol instructs us to broadcast Kᵢ and Gᵢ, but the protocol we implement
// cannot handle identify aborts since we are in a point to point model.
// We do as described in [LN18].
//
// In the next round, we send a hash of all the {Kⱼ,Gⱼ}ⱼ.
// In two rounds, we compare the hashes received and if they are different then we abort.
func (r *round1) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Retreive Paillier Key to encode K and Gamma
	kopts, err := keyopts.NewOptions().Set("id", r.cfg.KeyID(), "partyid", string(r.SelfID()))
	if err != nil {
		return nil, errors.WithMessage(err, "sign.round1.Finalize: failed to create options")
	}

	paillierKey, err := r.paillier_km.GetKey(kopts)
	if err != nil {
		return r, err
	}

	sopts, err := keyopts.NewOptions().Set("id", r.cfg.ID(), "partyid", string(r.SelfID()))
	if err != nil {
		return nil, errors.WithMessage(err, "sign.round1.Finalize: failed to create options")
	}

	// Generate Gamma ECDSA key to mask K and store its SKI to Gamma keyrpository
	if _, err := r.gamma.GenerateKey(sopts); err != nil {
		return r, err
	}

	// Encode Gamma using Paillier Key
	gammaPEK, err := r.gamma.EncodeByPaillier(paillierKey.PublicKey(), sopts)
	if err != nil {
		return r, err
	}
	if _, err := r.gamma_pek.Import(gammaPEK, sopts); err != nil {
		return r, err
	}

	// Generate K Scalar using ecdsa keymanager and store its SKI to K keyrepository
	if _, err := r.signK.GenerateKey(sopts); err != nil {
		return r, err
	}

	// Encode K using Paillier Key
	KSharePEK, err := r.signK.EncodeByPaillier(paillierKey.PublicKey(), sopts)
	if err != nil {
		return nil, err
	}
	if _, err := r.signK_pek.Import(KSharePEK, sopts); err != nil {
		return r, err
	}

	otherIDs := r.OtherPartyIDs()
	broadcastMsg := broadcast2{K: KSharePEK.Encoded(), G: gammaPEK.Encoded()}
	if err := r.BroadcastMessage(out, &broadcastMsg); err != nil {
		return r, err
	}
	errors := r.Pool.Parallelize(len(otherIDs), func(i int) interface{} {
		j := otherIDs[i]

		partyKopts, err := keyopts.NewOptions().Set("id", r.cfg.KeyID(), "partyid", string(j))
		if err != nil {
			return errors.WithMessage(err, "sign.round1.Finalize: failed to create options")
		}

		pedj, err := r.pedersen_km.GetKey(partyKopts)
		if err != nil {
			return err
		}
		proof, err := r.signK.NewZKEncProof(r.HashForID(r.SelfID()), KSharePEK, paillierKey.PublicKey(), pedj.PublicKey(), sopts)
		if err != nil {
			return err
		}

		if err := r.SendMessage(out, &message2{ProofEnc: proof}, j); err != nil {
			return err
		}
		return nil
	})
	for _, err := range errors {
		if err != nil {
			return r, err.(error)
		}
	}

	// update last round processed in StateManager
	if err := r.statemgr.SetLastRound(r.ID, int(r.Number())); err != nil {
		return r, err
	}

	return &round2{
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
		sigmgr:      r.sigmgr,
	}, nil
}

func (r *round1) CanFinalize() bool {
	// Verify if all parties commitments are received
	return true
}

// MessageContent implements round.Round.
func (round1) MessageContent() round.Content { return nil }

// Number implements round.Round.
func (round1) Number() round.Number { return 1 }

func (r *round1) Equal(other round.Round) bool {
	return true
}
