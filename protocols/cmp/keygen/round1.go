package keygen

import (
	"errors"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/party"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/lib/types"

	"github.com/mr-shifu/mpc-lib/pkg/common/commitstore"
	comm_commitment "github.com/mr-shifu/mpc-lib/pkg/mpc/common/commitment"
	comm_ecdsa "github.com/mr-shifu/mpc-lib/pkg/mpc/common/ecdsa"
	comm_elgamal "github.com/mr-shifu/mpc-lib/pkg/mpc/common/elgamal"
	comm_mpc_ks "github.com/mr-shifu/mpc-lib/pkg/mpc/common/mpckey"
	comm_paillier "github.com/mr-shifu/mpc-lib/pkg/mpc/common/paillier"
	comm_pedersen "github.com/mr-shifu/mpc-lib/pkg/mpc/common/pedersen"
	comm_rid "github.com/mr-shifu/mpc-lib/pkg/mpc/common/rid"
	comm_vss "github.com/mr-shifu/mpc-lib/pkg/mpc/common/vss"
)

var _ round.Round = (*round1)(nil)

type round1 struct {
	*round.Helper

	mpc_ks      comm_mpc_ks.MPCKeystore
	elgamal_km  comm_elgamal.ElgamalKeyManager
	paillier_km comm_paillier.PaillierKeyManager
	pedersen_km comm_pedersen.PedersenKeyManager
	ecdsa_km    comm_ecdsa.ECDSAKeyManager
	// ec_vss_km   comm_ecdsa.ECDSAKeyManager
	vss_mgr     comm_vss.VssKeyManager
	rid_km      comm_rid.RIDKeyManager
	chainKey_km comm_rid.RIDKeyManager
	commit_mgr  comm_commitment.CommitmentManager

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
	_, err := r.paillier_km.GenerateKey(r.ID, string(r.SelfID()))
	if err != nil {
		return nil, err
	}

	// derive Pedersen from Paillier
	pedersenKey, err := r.paillier_km.DerivePedersenKey(r.ID, string(r.SelfID()))
	if err != nil {
		return nil, err
	}
	r.pedersen_km.ImportKey(r.ID, string(r.SelfID()), pedersenKey)

	// generate ElGamal key
	elgamlKey, err := r.elgamal_km.GenerateKey(r.ID, string(r.SelfID()))
	if err != nil {
		return nil, err
	}

	// save our own share already so we are consistent with what we receive from others
	key, err := r.ecdsa_km.GetKey(r.ID, string(r.SelfID()))
	if err != nil {
		return nil, err
	}
	vssKey, err := key.VSS()
	if err != nil {
		return nil, err
	}

	// generate VSS Share
	if err := r.vss_mgr.GenerateVSSShare(r.ID, r.SelfID(), r.SelfID(), r.Group()); err != nil {
		return nil, err
	}

	// generate Schnorr randomness
	schnorrCommitment, err := key.NewSchnorrCommitment()
	if err != nil {
		return nil, err
	}

	// Sample RIDᵢ
	selfRID, err := r.rid_km.GenerateKey(r.ID, string(r.SelfID()))
	if err != nil {
		return nil, err
	}

	chainKey, err := r.chainKey_km.GenerateKey(r.ID, string(r.SelfID()))
	if err != nil {
		return nil, err
	}

	vssExponents, err := vssKey.Exponents()
	if err != nil {
		return nil, err
	}

	// TODO: make Commit to accept Key.Public() instead of key.PublicKeyRaw()
	SelfCommitment, Decommitment, err := r.Hash().Clone().Commit(
		selfRID,
		chainKey,
		vssExponents,
		elgamlKey.PublicKey(),
		pedersenKey.PublicKey(),
		schnorrCommitment,
	)
	if err != nil {
		return r, errors.New("failed to commit")
	}

	if err := r.commit_mgr.Import(r.ID, r.SelfID(), &commitstore.Commitment{
		Commitment:   SelfCommitment,
		Decommitment: Decommitment,
	}); err != nil {
		return r, err
	}

	// should be broadcast but we don't need that here
	msg := &broadcast2{Commitment: SelfCommitment}
	err = r.BroadcastMessage(out, msg)
	if err != nil {
		return r, err
	}

	nextRound := &round2{
		round1:             r,
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
