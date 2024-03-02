package keygen

import (
	"errors"

	"github.com/mr-shifu/mpc-lib/core/hash"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/party"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/lib/types"

	comm_ecdsa "github.com/mr-shifu/mpc-lib/pkg/mpc/common/ecdsa"
	comm_elgamal "github.com/mr-shifu/mpc-lib/pkg/mpc/common/elgamal"
	comm_mpc_ks "github.com/mr-shifu/mpc-lib/pkg/mpc/common/mpckey"
	comm_paillier "github.com/mr-shifu/mpc-lib/pkg/mpc/common/paillier"
	comm_pedersen "github.com/mr-shifu/mpc-lib/pkg/mpc/common/pedersen"
	comm_rid "github.com/mr-shifu/mpc-lib/pkg/mpc/common/rid"
)

var _ round.Round = (*round1)(nil)

type round1 struct {
	*round.Helper

	mpc_ks      comm_mpc_ks.MPCKeystore
	elgamal_km  comm_elgamal.ElgamalKeyManager
	paillier_km comm_paillier.PaillierKeyManager
	pedersen_km comm_pedersen.PedersenKeyManager
	ecdsa_km    comm_ecdsa.ECDSAKeyManager
	rid_km      comm_rid.RIDKeyManager
	chainKey_km comm_rid.RIDKeyManager

	// PreviousSecretECDSA = sk'ᵢ
	// Contains the previous secret ECDSA key share which is being refreshed
	// Keygen:  sk'ᵢ = nil
	// Refresh: sk'ᵢ = sk'ᵢ
	PreviousSecretECDSA curve.Scalar

	// PreviousPublicSharesECDSA[j] = pk'ⱼ
	// Keygen:  pk'ⱼ = nil
	// Refresh: pk'ⱼ = pk'ⱼ
	PreviousPublicSharesECDSA map[party.ID]curve.Point

	// PreviousChainKey contains the chain key, if we're refreshing
	//
	// In that case, we will simply use the previous chain key at the very end.
	PreviousChainKey types.RID
}

// VerifyMessage implements round.Round.
func (r *round1) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (r *round1) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
//
// - sample Paillier (pᵢ, qᵢ)
// - sample Pedersen Nᵢ, sᵢ, tᵢ
// - sample aᵢ  <- 𝔽
// - set Aᵢ = aᵢ⋅G
// - compute Fᵢ(X) = fᵢ(X)⋅G
// - sample ridᵢ <- {0,1}ᵏ
// - sample cᵢ <- {0,1}ᵏ
// - commit to message.
func (r *round1) Finalize(out chan<- *round.Message) (round.Session, error) {
	// generate Paillier and Pedersen
	_, err := r.paillier_km.GenerateKey(r.KeyID, string(r.SelfID()))
	if err != nil {
		return nil, err
	}

	// derive Pedersen from Paillier
	pedersenKey, err := r.paillier_km.DerivePedersenKey(r.KeyID, string(r.SelfID()))
	if err != nil {
		return nil, err
	}
	pedersen_kb, err := pedersenKey.Bytes()
	if err != nil {
		return nil, err
	}
	r.pedersen_km.ImportKey(r.KeyID, string(r.SelfID()), pedersen_kb)

	// generate ElGamal key
	elgamlKey, err := r.elgamal_km.GenerateKey(r.KeyID, string(r.SelfID()))
	if err != nil {
		return nil, err
	}

	// save our own share already so we are consistent with what we receive from others
	key, err := r.ecdsa_km.GetKey(r.KeyID, string(r.SelfID()))
	if err != nil {
		return nil, err
	}
	vssKey, err := key.VSS()
	if err != nil {
		return nil, err
	}
	if _, err := vssKey.Evaluate(r.SelfID().Scalar(r.Group())); err != nil {
		return nil, err
	}

	// generate Schnorr randomness
	schnorrCommitment, err := key.NewSchnorrCommitment()
	if err != nil {
		return nil, err
	}

	// Sample RIDᵢ
	selfRID, err := r.rid_km.GenerateKey(r.KeyID, string(r.SelfID()))
	if err != nil {
		return nil, err
	}

	chainKey, err := r.chainKey_km.GenerateKey(r.KeyID, string(r.SelfID()))
	if err != nil {
		return nil, err
	}

	// commit to data in message 2
	// TODO Hash func must be fixed to handle cryptosuite keys
	pedersen_bytes, err := pedersenKey.Bytes()
	if err != nil {
		return nil, err
	}
	elgamal_bytes, err := elgamlKey.Bytes()
	if err != nil {
		return nil, err
	}
	vssKey_bytes, err := vssKey.Bytes()
	if err != nil {
		return nil, err
	}
	selfRID_bytes, err := selfRID.Bytes()
	if err != nil {
		return nil, err
	}
	chainKey_bytes, err := chainKey.Bytes()
	if err != nil {
		return nil, err
	}

	SelfCommitment, Decommitment, err := r.HashForID(r.SelfID()).Commit(
		selfRID_bytes, chainKey_bytes, vssKey_bytes, schnorrCommitment, elgamal_bytes, pedersen_bytes)
	if err != nil {
		return r, errors.New("failed to commit")
	}

	// should be broadcast but we don't need that here
	msg := &broadcast2{Commitment: SelfCommitment}
	err = r.BroadcastMessage(out, msg)
	if err != nil {
		return r, err
	}

	nextRound := &round2{
		round1:             r,
		mpc_ks:             r.mpc_ks,
		elgamal_km:         r.elgamal_km,
		paillier_km:        r.paillier_km,
		pedersen_km:        r.pedersen_km,
		ecdsa_km:           r.ecdsa_km,
		rid_km:             r.rid_km,
		chainKey_km:        r.chainKey_km,
		Commitments:        map[party.ID]hash.Commitment{r.SelfID(): SelfCommitment},
		Decommitment:       Decommitment,
		MessageBroadcasted: make(map[party.ID]bool),
	}
	return nextRound, nil
}

func (r *round1) CanFinalize() bool {
	// Verify if all parties commitments are received
	return true
}

// PreviousRound implements round.Round.
func (round1) PreviousRound() round.Round { return nil }

// MessageContent implements round.Round.
func (round1) MessageContent() round.Content { return nil }

// Number implements round.Round.
func (round1) Number() round.Number { return 1 }
