package keygen

import (
	"encoding/hex"
	"errors"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/paillier"
	"github.com/mr-shifu/mpc-lib/core/party"
	zkfac "github.com/mr-shifu/mpc-lib/core/zk/fac"
	zkmod "github.com/mr-shifu/mpc-lib/core/zk/mod"
	zkprm "github.com/mr-shifu/mpc-lib/core/zk/prm"
	"github.com/mr-shifu/mpc-lib/lib/round"
	comm_ecdsa "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/ecdsa"
	comm_keyopts "github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
	sw_ecdsa "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/protocols/cmp/config"
)

var _ round.Round = (*round4)(nil)

type round4 struct {
	*round3

	// Number of Broacasted Messages received
	MessageBroadcasted map[party.ID]bool
	MessagesForwarded  map[party.ID]bool
}

type message4 struct {
	// Share = Encᵢ(x) is the encryption of the receivers share
	Share *paillier.Ciphertext
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
	from := msg.From
	body, ok := msg.Content.(*broadcast4)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	fromOpts := keyopts.Options{}
	fromOpts.Set("id", r.ID, "partyid", string(from))

	// verify zkmod
	ped, err := r.pedersen_km.GetKey(fromOpts)
	if err != nil {
		return err
	}
	paillier, err := r.paillier_km.GetKey(fromOpts)
	if err != nil {
		return err
	}
	if !paillier.VerifyZKMod(body.Mod, r.HashForID(from), r.Pool) {
		return errors.New("failed to validate mod proof")
	}

	// verify zkprm
	if !ped.VerifyProof(r.HashForID(from), r.Pool, body.Prm) {
		return errors.New("failed to validate prm proof")
	}

	// Mark the message as received
	r.MessageBroadcasted[from] = true

	return nil
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

	selfOpts := keyopts.Options{}
	selfOpts.Set("id", r.ID, "partyid", string(r.SelfID()))

	fromOpts := keyopts.Options{}
	fromOpts.Set("id", r.ID, "partyid", string(from))

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
	from, body := msg.From, msg.Content.(*message4)

	selfOpts := keyopts.Options{}
	selfOpts.Set("id", r.ID, "partyid", string(r.SelfID()))

	fromOpts := keyopts.Options{}
	fromOpts.Set("id", r.ID, "partyid", string(from))

	// decrypt share
	paillierKey, err := r.paillier_km.GetKey(selfOpts)
	if err != nil {
		return err
	}
	DecryptedShare, err := paillierKey.Decode(body.Share)
	if err != nil {
		return err
	}
	Share := r.Group().NewScalar().SetNat(DecryptedShare.Mod(r.Group().Order()))
	if DecryptedShare.Eq(curve.MakeInt(Share)) != 1 {
		return errors.New("decrypted share is not in correct range")
	}

	// verify share with VSS
	ecKey, err := r.ecdsa_km.GetKey(fromOpts)
	if err != nil {
		return err
	}
	vssKey, err := ecKey.VSS(fromOpts)
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

	vssShareOpts := keyopts.Options{}
	vssShareOpts.Set("id", hex.EncodeToString(vssKey.SKI()), "partyid", string(r.SelfID()))
	vssShareKey := sw_ecdsa.NewECDSAKey(Share, PublicShare, r.Group())
	if _, err := r.ec_vss_km.ImportKey(vssShareKey, vssShareOpts); err != nil {
		return err
	}

	// Mark the message as received
	r.MessagesForwarded[from] = true

	return nil
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
	if len(r.MessageBroadcasted) != r.N()-1 || len(r.MessagesForwarded) != r.N()-1 {
		return nil, round.ErrNotEnoughMessages
	}

	opts := keyopts.Options{}
	opts.Set("id", r.ID, "partyid", string(r.SelfID()))

	// Calculate MPC public Key
	mpcPublicKey := r.Group().NewPoint()
	for _, partyID := range r.PartyIDs() {
		partyOpts := keyopts.Options{}
		partyOpts.Set("id", r.ID, "partyid", string(partyID))

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
	rootOpts := keyopts.Options{}
	rootOpts.Set("id", r.ID, "partyid", "ROOT")
	k := r.ecdsa_km.NewKey(nil, mpcPublicKey, r.Group())
	if _, err := r.ecdsa_km.ImportKey(k, rootOpts); err != nil {
		return nil, err
	}

	// Sum all VSS Exponents Shares to generate MPC VSS Exponent
	// var allExponents []*polynomial.Exponent
	vssOptsList := make([]comm_keyopts.Options, 0)
	for _, partyID := range r.PartyIDs() {
		partyOpts := keyopts.Options{}
		partyOpts.Set("id", r.ID, "partyid", string(partyID))
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
		vssPartyOpts := keyopts.Options{}

		vssPartyOpts.Set("id", hex.EncodeToString(vssPoly.SKI()), "partyid", string(j))

		vssPub, err := vssPoly.EvaluateByExponents(j.Scalar(r.Group()))
		if err != nil {
			return nil, err
		}
		vssKeyShare := sw_ecdsa.NewECDSAKey(nil, vssPub, r.Group())
		if _, err := r.ec_vss_km.ImportKey(vssKeyShare, vssPartyOpts); err != nil {
			return nil, err
		}
	}

	// Sum all VSS shares to generate MPC VSS Share
	var vss_shares []comm_ecdsa.ECDSAKey
	for _, j := range r.OtherPartyIDs() {
		partyOpts := keyopts.Options{}
		partyOpts.Set("id", r.ID, "partyid", string(j))

		vss, err := r.vss_mgr.GetSecrets(partyOpts)
		if err != nil {
			return nil, err
		}

		vssOpts := keyopts.Options{}
		vssOpts.Set("id", hex.EncodeToString(vss.SKI()), "partyid", string(r.SelfID()))
		vss_share, err := r.ec_vss_km.GetKey(vssOpts)
		if err != nil {
			return nil, err
		}
		vss_shares = append(vss_shares, vss_share)
	}
	vss, err := r.vss_mgr.GetSecrets(opts)
	if err != nil {
		return nil, err
	}
	vssOpts := keyopts.Options{}
	vssOpts.Set("id", hex.EncodeToString(vss.SKI()), "partyid", string(r.SelfID()))
	selfVSSShare, err := r.ec_vss_km.GetKey(vssOpts)
	if err != nil {
		return nil, err
	}
	vssSharePrivateKey := selfVSSShare.AddKeys(vss_shares...)
	vssSharePublicKey := vssSharePrivateKey.ActOnBase()
	vssShareKey := sw_ecdsa.NewECDSAKey(vssSharePrivateKey, vssSharePublicKey, r.Group())
	rootVssOpts := keyopts.Options{}
	rootVssOpts.Set("id", hex.EncodeToString(rootVss.SKI()), "partyid", "ROOT")
	if _, err := r.ec_vss_km.ImportKey(vssShareKey, rootVssOpts); err != nil {
		return nil, err
	}

	// compute the new public key share Xⱼ = F(j) (+X'ⱼ if doing a refresh)
	mpcKey, err := r.ecdsa_km.GetKey(rootOpts)
	if err != nil {
		return nil, err
	}
	mpcVSSKey, err := mpcKey.VSS(rootOpts)
	if err != nil {
		return nil, err
	}
	PublicData := make(map[party.ID]*config.Public, len(r.PartyIDs()))
	for _, j := range r.PartyIDs() {
		partyOpts := keyopts.Options{}
		partyOpts.Set("id", r.ID, "partyid", string(j))

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

		PublicData[j] = &config.Public{
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
	UpdatedConfig := &config.Config{
		Group:     r.Group(),
		ID:        r.SelfID(),
		Threshold: r.Threshold(),
		ECDSA:     vssSharePrivateKey,
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

	// proof := r.SchnorrRand.Prove(h, PublicData[r.SelfID()].ECDSA, UpdatedSecretECDSA, nil)
	ecKey, err := r.ecdsa_km.GetKey(opts)
	if err != nil {
		return nil, err
	}
	proof, err := ecKey.GenerateSchnorrProof(h)
	if err != nil {
		return r, err
	}

	// send to all
	err = r.BroadcastMessage(out, &broadcast5{SchnorrResponse: proof})
	if err != nil {
		return r, err
	}

	r.UpdateHashState(UpdatedConfig)

	// update last round processed in StateManager
	if err := r.statemanger.SetLastRound(r.ID, int(r.Number())); err != nil {
		return r, err
	}

	return &round5{
		round4:             r,
		UpdatedConfig:      UpdatedConfig,
		MessageBroadcasted: make(map[party.ID]bool),
	}, nil
}

func (r *round4) CanFinalize() bool {
	// Verify if all parties commitments are received
	return len(r.MessageBroadcasted) == r.N()-1 && len(r.MessagesForwarded) == r.N()-1
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
