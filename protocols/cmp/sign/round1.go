package sign

import (
	"github.com/mr-shifu/mpc-lib/core/party"
	"github.com/mr-shifu/mpc-lib/lib/round"
	comm_hash "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
	comm_config "github.com/mr-shifu/mpc-lib/pkg/mpc/common/config"
	comm_ecdsa "github.com/mr-shifu/mpc-lib/pkg/mpc/common/ecdsa"
	comm_mta "github.com/mr-shifu/mpc-lib/pkg/mpc/common/mta"
	comm_paillier "github.com/mr-shifu/mpc-lib/pkg/mpc/common/paillier"
	comm_pedersen "github.com/mr-shifu/mpc-lib/pkg/mpc/common/pedersen"
	comm_pek "github.com/mr-shifu/mpc-lib/pkg/mpc/common/pek"
	comm_result "github.com/mr-shifu/mpc-lib/pkg/mpc/common/result"
	comm_vss "github.com/mr-shifu/mpc-lib/pkg/mpc/common/vss"
)

var _ round.Round = (*round1)(nil)

type round1 struct {
	*round.Helper

	cfg       comm_config.SignConfig
	signature comm_result.Signature

	hash_mgr    comm_hash.HashManager
	paillier_km comm_paillier.PaillierKeyManager
	pedersen_km comm_pedersen.PedersenKeyManager

	ec comm_ecdsa.ECDSAKeyManager
	// ec_vss   comm_ecdsa.ECDSAKeyManager
	gamma    comm_ecdsa.ECDSAKeyManager
	signK    comm_ecdsa.ECDSAKeyManager
	delta    comm_ecdsa.ECDSAKeyManager
	chi      comm_ecdsa.ECDSAKeyManager
	bigDelta comm_ecdsa.ECDSAKeyManager

	vss_mgr comm_vss.VssKeyManager

	gamma_pek comm_pek.PaillierEncodedKeyManager
	signK_pek comm_pek.PaillierEncodedKeyManager

	delta_mta comm_mta.MtAManager
	chi_mta   comm_mta.MtAManager

	sigma comm_result.SigmaStore

	Message []byte
}

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
	paillierKey, err := r.paillier_km.GetKey(r.cfg.KeyID(), string(r.SelfID()))
	if err != nil {
		return r, err
	}

	// Generate Gamma ECDSA key to mask K and store its SKI to Gamma keyrpository
	gamma, err := r.gamma.GenerateKey(r.cfg.ID(), string(r.SelfID()))
	if err != nil {
		return r, err
	}

	// Encode Gamma using Paillier Key
	gammaPEK, err := gamma.EncodeByPaillier(paillierKey.PublicKey())
	if err != nil {
		return r, err
	}
	if _, err := r.gamma_pek.ImportKey(r.cfg.ID(), string(r.SelfID()), gammaPEK); err != nil {
		return r, err
	}

	// Generate K Scalar using ecdsa keymanager and store its SKI to K keyrepository
	KShare, err := r.signK.GenerateKey(r.cfg.ID(), string(r.SelfID()))
	if err != nil {
		return r, err
	}

	// Encode K using Paillier Key
	KSharePEK, err := KShare.EncodeByPaillier(paillierKey.PublicKey())
	if err != nil {
		return nil, err
	}
	if _, err := r.signK_pek.ImportKey(r.cfg.ID(), string(r.SelfID()), KSharePEK); err != nil {
		return r, err
	}

	otherIDs := r.OtherPartyIDs()
	broadcastMsg := broadcast2{K: KSharePEK.Encoded(), G: gammaPEK.Encoded()}
	if err := r.BroadcastMessage(out, &broadcastMsg); err != nil {
		return r, err
	}
	errors := r.Pool.Parallelize(len(otherIDs), func(i int) interface{} {
		j := otherIDs[i]

		pedj, err := r.pedersen_km.GetKey(r.cfg.KeyID(), string(j))
		if err != nil {
			return err
		}
		proof, err := KShare.NewZKEncProof(r.HashForID(r.SelfID()), KSharePEK, paillierKey.PublicKey(), pedj.PublicKey())
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

	return &round2{
		round1:             r,
		MessageBroadcasted: make(map[party.ID]bool),
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
