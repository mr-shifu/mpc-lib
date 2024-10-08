package keygen

import (
	"encoding/hex"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
	core_paillier "github.com/mr-shifu/mpc-lib/core/paillier"
	"github.com/mr-shifu/mpc-lib/core/party"
	zkfac "github.com/mr-shifu/mpc-lib/core/zk/fac"
	zkmod "github.com/mr-shifu/mpc-lib/core/zk/mod"
	zkprm "github.com/mr-shifu/mpc-lib/core/zk/prm"
	"github.com/mr-shifu/mpc-lib/lib/round"
	comm_keyopts "github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
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
	"github.com/pkg/errors"
)

var _ round.Round = (*round4)(nil)

type round4 struct {
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
}

type message4 struct {
	// Share = Encᵢ(x) is the encryption of the receivers share
	Share *core_paillier.Ciphertext
	Fac   *zkfac.Proof
}

type broadcast4 struct {
	round.NormalBroadcastContent
	Mod *zkmod.Proof
	Prm *zkprm.Proof
}

// StoreBroadcastMessage implements round.BroadcastRound.
//
// - verify Mod, Prm proof for N
func (r *round4) StoreBroadcastMessage(msg round.Message) error {
	content, err := r.validateBroadcastMessage(msg)
	if err != nil {
		return errors.WithMessage(err, "keygen.round4.StoreBroadcastMessage: failed to validate message")
	}

	from := msg.From

	fromOpts, err := keyopts.NewOptions().Set("id", r.ID, "partyid", string(from))
	if err != nil {
		return errors.WithMessage(err, "keygen.round4.StoreBroadcastMessage: failed to create options")
	}
	// verify zkmod
	ped, err := r.pedersen_km.GetKey(fromOpts)
	if err != nil {
		return err
	}
	paillier, err := r.paillier_km.GetKey(fromOpts)
	if err != nil {
		return err
	}
	if !paillier.VerifyZKMod(content.Mod, r.HashForID(from), r.Pool) {
		return errors.New("keygen.round4.StoreBroadcastMessage: failed to validate mod proof")
	}

	// verify zkprm
	if !ped.VerifyProof(r.HashForID(from), r.Pool, content.Prm) {
		return errors.New("failed to validate prm proof")
	}

	// Mark the message as received
	if err := r.bcstmgr.Import(
		r.bcstmgr.NewMessage(r.ID, int(r.Number()), string(msg.From), true),
	); err != nil {
		return err
	}

	return nil
}

func (r *round4) validateBroadcastMessage(msg round.Message) (*broadcast4, error) {
	content, ok := msg.Content.(*broadcast4)
	if !ok || content == nil {
		return nil, round.ErrInvalidContent
	}
	if content.Mod == nil {
		return nil, errors.New("keygen.round4.validateBroadcastMessage: mod is nil")
	}
	if content.Prm == nil {
		return nil, errors.New("keygen.round4.validateBroadcastMessage: prm is nil")
	}
	return content, nil
}

// VerifyMessage implements round.Round.
//
// - verify validity of share ciphertext.
func (r *round4) VerifyMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*message4)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	selfOpts, err := keyopts.NewOptions().Set("id", r.ID, "partyid", string(r.SelfID()))
	if err != nil {
		return errors.WithMessage(err, "keygen.round4.VerifyMessage: failed to create options")
	}

	fromOpts, err := keyopts.NewOptions().Set("id", r.ID, "partyid", string(from))
	if err != nil {
		return errors.WithMessage(err, "keygen.round4.VerifyMessage: failed to create options")
	}

	paillierKey, err := r.paillier_km.GetKey(selfOpts)
	if err != nil {
		return err
	}
	if !paillierKey.ValidateCiphertexts(body.Share) {
		return errors.New("invalid ciphertext")
	}

	ped, err := r.pedersen_km.GetKey(selfOpts)
	if err != nil {
		return err
	}

	// verify zkfac
	paillierj, err := r.paillier_km.GetKey(fromOpts)
	if err != nil {
		return err
	}
	if !paillierKey.VerifyZKFAC(body.Fac, zkfac.Public{
		N:   paillierj.PublicKey().ParamN(),
		Aux: ped.PublicKeyRaw(),
	}, r.HashForID(from)) {
		return errors.New("failed to validate fac proof")
	}

	return nil
}

// StoreMessage implements round.Round.
//
// Since this message is only intended for us, we need to do the VSS verification here.
// - check that the decrypted share did not overflow.
// - check VSS condition.
// - save share.
func (r *round4) StoreMessage(msg round.Message) error {
	content, err := r.validateMessage(msg)
	if err != nil {
		return errors.WithMessage(err, "keygen.round4.StoreMessage: failed to validate message")
	}

	from := msg.From

	selfOpts, err := keyopts.NewOptions().Set("id", r.ID, "partyid", string(r.SelfID()))
	if err != nil {
		return errors.WithMessage(err, "keygen.round4.StoreMessage: failed to create options")
	}

	fromOpts, err := keyopts.NewOptions().Set("id", r.ID, "partyid", string(from))
	if err != nil {
		return errors.WithMessage(err, "keygen.round4.StoreMessage: failed to create options")
	}

	// decrypt share
	paillierKey, err := r.paillier_km.GetKey(selfOpts)
	if err != nil {
		return err
	}
	DecryptedShare, err := paillierKey.Decode(content.Share)
	if err != nil {
		return err
	}
	Share := r.Group().NewScalar().SetNat(DecryptedShare.Mod(r.Group().Order()))
	if DecryptedShare.Eq(curve.MakeInt(Share)) != 1 {
		return errors.New("decrypted share is not in correct range")
	}

	// verify share with VSS
	vssKey, err := r.ecdsa_km.GetVss(fromOpts)
	if err != nil {
		return err
	}
	ExpectedPublicShare, err := vssKey.EvaluateByExponents(r.SelfID().Scalar(r.Group())) // Fⱼ(i)
	if err != nil {
		return err
	}
	PublicShare := Share.ActOnBase()
	// X == Fⱼ(i)
	if !PublicShare.Equal(ExpectedPublicShare) {
		return errors.New("failed to validate VSS share")
	}

	vssShareOpts, err := keyopts.NewOptions().Set("id", hex.EncodeToString(vssKey.SKI()), "partyid", string(r.SelfID()))
	if err != nil {
		return errors.WithMessage(err, "keygen.round4.StoreMessage: failed to create options")
	}
	vssShareKey := ecdsa.NewKey(Share, PublicShare, r.Group())
	if _, err := r.ec_vss_km.ImportKey(vssShareKey, vssShareOpts); err != nil {
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

func (r *round4) validateMessage(msg round.Message) (*message4, error) {
	content, ok := msg.Content.(*message4)
	if !ok || content == nil {
		return nil, round.ErrInvalidContent
	}
	if content.Share == nil {
		return nil, errors.New("keygen.round4.validateMessage: share is nil")
	}
	if content.Fac == nil {
		return nil, errors.New("keygen.round4.validateMessage: fac is nil")
	}
	return content, nil
}

// Finalize implements round.Round
//
// - sum of all received shares
// - compute group public key and individual public keys
// - recompute config SSID
// - validate Config
// - write new ssid hash to old hash state
// - create proof of knowledge of secret.
func (r *round4) Finalize(out chan<- *round.Message) (round.Session, error) {
	// check if we received all messages
	if !r.CanFinalize() {
		return nil, round.ErrNotEnoughMessages
	}

	opts, err := keyopts.NewOptions().Set("id", r.ID, "partyid", string(r.SelfID()))
	if err != nil {
		return nil, errors.WithMessage(err, "keygen.round4.Finalize: failed to create options")
	}

	// Calculate MPC public Key
	mpcPublicKey := r.Group().NewPoint()
	for _, partyID := range r.PartyIDs() {
		partyOpts, err := keyopts.NewOptions().Set("id", r.ID, "partyid", string(partyID))
		if err != nil {
			return nil, errors.WithMessage(err, "keygen.round4.Finalize: failed to create options")
		}

		vssKey, err := r.vss_mgr.GetSecrets(partyOpts)
		if err != nil {
			return nil, err
		}
		exp, err := vssKey.ExponentsRaw()
		if err != nil {
			return nil, err
		}
		pub := exp.Constant()
		mpcPublicKey = mpcPublicKey.Add(pub)
	}

	// Import MPC public Key
	rootOpts, err := keyopts.NewOptions().Set("id", r.ID, "partyid", "ROOT")
	if err != nil {
		return nil, errors.WithMessage(err, "keygen.round4.Finalize: failed to create options")
	}
	k := ecdsa.NewKey(nil, mpcPublicKey, r.Group())
	if _, err := r.ecdsa_km.ImportKey(k, rootOpts); err != nil {
		return nil, err
	}

	// Sum all VSS Exponents Shares to generate MPC VSS Exponent
	// var allExponents []*polynomial.Exponent
	vssOptsList := make([]comm_keyopts.Options, 0)
	for _, partyID := range r.PartyIDs() {
		partyOpts, err := keyopts.NewOptions().Set("id", r.ID, "partyid", string(partyID))
		if err != nil {
			return nil, errors.WithMessage(err, "keygen.round4.Finalize: failed to create options")
		}
		vssOptsList = append(vssOptsList, partyOpts)
	}
	rootVss, err := r.vss_mgr.SumExponents(vssOptsList...)
	if err != nil {
		return nil, err
	}
	_, err = r.vss_mgr.ImportSecrets(rootVss, rootOpts)
	if err != nil {
		return nil, err
	}

	vssPoly, err := r.vss_mgr.GetSecrets(rootOpts)
	if err != nil {
		return nil, err
	}
	for _, j := range r.PartyIDs() {
		vssPartyOpts, err := keyopts.NewOptions().Set("id", hex.EncodeToString(vssPoly.SKI()), "partyid", string(j))
		if err != nil {
			return nil, errors.WithMessage(err, "keygen.round4.Finalize: failed to create options")
		}

		vssPub, err := vssPoly.EvaluateByExponents(j.Scalar(r.Group()))
		if err != nil {
			return nil, err
		}
		vssKeyShare := ecdsa.NewKey(nil, vssPub, r.Group())
		if _, err := r.ec_vss_km.ImportKey(vssKeyShare, vssPartyOpts); err != nil {
			return nil, err
		}
	}

	// Sum all VSS shares to generate MPC VSS Share
	vssOptsList = make([]comm_keyopts.Options, 0)
	for _, j := range r.OtherPartyIDs() {
		partyOpts, err := keyopts.NewOptions().Set("id", r.ID, "partyid", string(j))
		if err != nil {
			return nil, errors.WithMessage(err, "keygen.round4.Finalize: failed to create options")
		}

		vss, err := r.vss_mgr.GetSecrets(partyOpts)
		if err != nil {
			return nil, err
		}

		vssOpts, err := keyopts.NewOptions().Set("id", hex.EncodeToString(vss.SKI()), "partyid", string(r.SelfID()))
		if err != nil {
			return nil, errors.WithMessage(err, "keygen.round4.Finalize: failed to create options")
		}
		vssOptsList = append(vssOptsList, vssOpts)
	}
	vss, err := r.vss_mgr.GetSecrets(opts)
	if err != nil {
		return nil, err
	}
	vssOpts, err := keyopts.NewOptions().Set("id", hex.EncodeToString(vss.SKI()), "partyid", string(r.SelfID()))
	if err != nil {
		return nil, errors.WithMessage(err, "keygen.round4.Finalize: failed to create options")
	}
	vssOptsList = append(vssOptsList, vssOpts)
	vssShareKey, err := r.ec_vss_km.SumKeys(vssOptsList...)
	if err != nil {
		return nil, errors.WithMessage(err, "keygen.round4.Finalize: failed to sum vss keys")
	}
	rootVssOpts, err := keyopts.NewOptions().Set("id", hex.EncodeToString(rootVss.SKI()), "partyid", "ROOT")
	if err != nil {
		return nil, errors.WithMessage(err, "keygen.round4.Finalize: failed to create options")
	}
	if _, err := r.ec_vss_km.ImportKey(vssShareKey, rootVssOpts); err != nil {
		return nil, err
	}

	// compute the new public key share Xⱼ = F(j) (+X'ⱼ if doing a refresh)
	mpcVSSKey, err := r.ecdsa_km.GetVss(rootOpts)
	if err != nil {
		return nil, err
	}
	PublicData := make(map[party.ID]*Public, len(r.PartyIDs()))
	for _, j := range r.PartyIDs() {
		partyOpts, err := keyopts.NewOptions().Set("id", r.ID, "partyid", string(j))
		if err != nil {
			return nil, errors.WithMessage(err, "keygen.round4.Finalize: failed to create options")
		}

		elgamalj, err := r.elgamal_km.GetKey(partyOpts)
		if err != nil {
			return r, err
		}

		paillierj, err := r.paillier_km.GetKey(partyOpts)
		if err != nil {
			return r, err
		}

		pedersenj, err := r.pedersen_km.GetKey(partyOpts)
		if err != nil {
			return r, err
		}
		PublicECDSAShare, err := mpcVSSKey.EvaluateByExponents(j.Scalar(r.Group()))
		if err != nil {
			return r, err
		}

		PublicData[j] = &Public{
			ECDSA:    PublicECDSAShare,
			ElGamal:  elgamalj.PublicKeyRaw(),
			Paillier: paillierj.PublicKeyRaw(),
			Pedersen: pedersenj.PublicKeyRaw(),
		}
	}

	// mpcVSSShare, err := mpcVSSKey.GetShare(r.SelfID().Scalar(r.Group()))
	// if err != nil {
	// 	return r, err
	// }

	rid, err := r.rid_km.GetKey(rootOpts)
	if err != nil {
		return nil, err
	}
	chainKey, err := r.chainKey_km.GetKey(rootOpts)
	if err != nil {
		return nil, err
	}

	// TODO elgamal and paillier secret key is missed here
	UpdatedConfig := &Config{
		Group:     r.Group(),
		ID:        r.SelfID(),
		Threshold: r.Threshold(),
		// ECDSA:     vssSharePrivateKey,
		// ElGamal:   r.ElGamalSecret,
		// Paillier:  r.PaillierSecret,
		RID:      rid.Raw(),
		ChainKey: chainKey.Raw(),
		Public:   PublicData,
	}

	// write new ssid to hash, to bind the Schnorr proof to this new config
	// Write SSID, selfID to temporary hash
	h := r.Hash().Clone()
	_ = h.WriteAny(UpdatedConfig, r.SelfID())

	proof, err := r.ecdsa_km.GenerateSchnorrResponse(h, opts)
	if err != nil {
		return r, err
	}

	// send to all
	err = r.BroadcastMessage(out, &broadcast5{SchnorrResponse: proof.Response().Z})
	if err != nil {
		return r, err
	}

	r.UpdateHashState(UpdatedConfig)

	// update last round processed in StateManager
	if err := r.statemanger.SetLastRound(r.ID, int(r.Number())); err != nil {
		return r, err
	}

	return &round5{
		Helper:        r.Helper,
		statemanger:   r.statemanger,
		msgmgr:        r.msgmgr,
		bcstmgr:       r.bcstmgr,
		elgamal_km:    r.elgamal_km,
		paillier_km:   r.paillier_km,
		pedersen_km:   r.pedersen_km,
		ecdsa_km:      r.ecdsa_km,
		ec_vss_km:     r.ec_vss_km,
		vss_mgr:       r.vss_mgr,
		rid_km:        r.rid_km,
		chainKey_km:   r.chainKey_km,
		commit_mgr:    r.commit_mgr,
		UpdatedConfig: UpdatedConfig,
	}, nil
}

func (r *round4) CanFinalize() bool {
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

// RoundNumber implements round.Content.
func (message4) RoundNumber() round.Number { return 4 }

// MessageContent implements round.Round.
func (round4) MessageContent() round.Content { return &message4{} }

// RoundNumber implements round.Content.
func (broadcast4) RoundNumber() round.Number { return 4 }

// BroadcastContent implements round.BroadcastRound.
func (round4) BroadcastContent() round.BroadcastContent { return &broadcast4{} }

// Number implements round.Round.
func (round4) Number() round.Number { return 4 }
