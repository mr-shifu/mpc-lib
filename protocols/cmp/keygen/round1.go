package keygen

import (
	"encoding/hex"

	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/pkg/errors"

	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/commitment"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/elgamal"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillier"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/pedersen"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/rid"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/message"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/state"
)

var _ round.Round = (*round1)(nil)

type round1 struct {
	*round.Helper

	statemanger state.MPCStateManager
	msgmgr      message.MessageManager
	bcstmgr     message.MessageManager
	elgamal_km  elgamal.ElgamalKeyManager
	paillier_km paillier.PaillierKeyManager
	pedersen_km pedersen.PedersenKeyManager
	ecdsa_km    ecdsa.ECDSAKeyManager
	ec_vss_km   ecdsa.ECDSAKeyManager
	vss_mgr     vss.VssKeyManager
	rid_km      rid.RIDManager
	chainKey_km rid.RIDManager
	commit_mgr  commitment.CommitmentManager

	// PreviousSecretECDSA = sk'ᵢ
	// Contains the previous secret ECDSA key share which is being refreshed
	// Keygen:  sk'ᵢ = nil
	// Refresh: sk'ᵢ = sk'ᵢ
	// PreviousSecretECDSA curve.Scalar

	// // PreviousPublicSharesECDSA[j] = pk'ⱼ
	// // Keygen:  pk'ⱼ = nil
	// // Refresh: pk'ⱼ = pk'ⱼ
	// PreviousPublicSharesECDSA map[party.ID]curve.Point

	// // PreviousChainKey contains the chain key, if we're refreshing
	// //
	// // In that case, we will simply use the previous chain key at the very end.
	// PreviousChainKey types.RID
}

// VerifyMessage implements round.Round.
func (r *round1) VerifyMessage(round.Message) error { return nil }

// StoreBroadcastMessage implements round.Round.
func (r *round1) StoreBroadcastMessage(round.Message) error { return nil }

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
	opts, err := keyopts.NewOptions().Set("id", r.ID, "partyid", string(r.SelfID()))
	if err != nil {
		return nil, errors.WithMessage(err, "cmp.Keygen.Round1: failed to create options")
	}

	paillierKey, err := r.paillier_km.GenerateKey(opts)
	if err != nil {
		return nil, err
	}

	// derive Pedersen from Paillier
	pedersenKey, err := paillierKey.DerivePedersenKey()
	if err != nil {
		return nil, err
	}
	if _, err := r.pedersen_km.ImportKey(pedersenKey, opts); err != nil {
		return nil, err
	}

	// generate ElGamal key
	elgamlKey, err := r.elgamal_km.GenerateKey(opts)
	if err != nil {
		return nil, err
	}

	// save our own share already so we are consistent with what we receive from others
	vssKey, err := r.ecdsa_km.GetVss(opts)
	if err != nil {
		return nil, err
	}

	// generate VSS Share
	share, err := r.vss_mgr.Evaluate(r.SelfID().Scalar(r.Group()), opts)
	if err != nil {
		return nil, err
	}
	sharePublic := share.ActOnBase()
	shareKey := ecdsa.NewKey(share, sharePublic, r.Group())
	vssOpts, err := keyopts.NewOptions().Set("id", hex.EncodeToString(vssKey.SKI()), "partyid", string(r.SelfID()))
	if err != nil {
		return nil, errors.WithMessage(err, "cmp.Keygen.Round1: failed to create options")
	}
	if _, err := r.ec_vss_km.ImportKey(shareKey, vssOpts); err != nil {
		return nil, err
	}

	// generate Schnorr randomness
	schProof, err := r.ecdsa_km.GenerateSchnorrCommitment(r.HashForID(r.SelfID()), opts)
	if err != nil {
		return nil, err
	}

	// Sample RIDᵢ
	selfRID, err := r.rid_km.GenerateKey(opts)
	if err != nil {
		return nil, err
	}

	chainKey, err := r.chainKey_km.GenerateKey(opts)
	if err != nil {
		return nil, err
	}

	vssExponents, err := vssKey.Exponents()
	if err != nil {
		return nil, err
	}

	SelfCommitment, Decommitment, err := r.Hash().Clone().Commit(
		selfRID,
		chainKey,
		vssExponents,
		elgamlKey.PublicKey(),
		pedersenKey.PublicKeyRaw().N(),
		pedersenKey.PublicKeyRaw().S(),
		pedersenKey.PublicKeyRaw().T(),
		schProof.Commitment(),
	)
	if err != nil {
		return r, errors.New("failed to commit")
	}

	cmt := r.commit_mgr.NewCommitment(SelfCommitment, Decommitment)
	if err := r.commit_mgr.Import(cmt, opts); err != nil {
		return r, err
	}

	// should be broadcast but we don't need that here
	msg := &broadcast2{Commitment: SelfCommitment}
	err = r.BroadcastMessage(out, msg)
	if err != nil {
		return r, err
	}

	// update last round processed in StateManager
	if err := r.statemanger.SetLastRound(r.ID, int(r.Number())); err != nil {
		return r, err
	}

	nextRound := &round2{
		Helper:      r.Helper,
		statemanger: r.statemanger,
		msgmgr:      r.msgmgr,
		bcstmgr:     r.bcstmgr,
		elgamal_km:  r.elgamal_km,
		paillier_km: r.paillier_km,
		pedersen_km: r.pedersen_km,
		ecdsa_km:    r.ecdsa_km,
		ec_vss_km:   r.ec_vss_km,
		vss_mgr:     r.vss_mgr,
		rid_km:      r.rid_km,
		chainKey_km: r.chainKey_km,
		commit_mgr:  r.commit_mgr,
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
