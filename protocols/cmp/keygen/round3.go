package keygen

import (
	"github.com/mr-shifu/mpc-lib/core/hash"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/math/polynomial"
	zkfac "github.com/mr-shifu/mpc-lib/core/zk/fac"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/lib/types"
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

var _ round.Round = (*round3)(nil)

type round3 struct {
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

type broadcast3 struct {
	round.NormalBroadcastContent
	// RID = RIDᵢ
	RID      types.RID
	C        types.RID
	EcdsaKey []byte
	// VSSPolynomial = Fᵢ(X) VSSPolynomial
	VSSPolynomial []byte
	// SchnorrCommitments = Aᵢ Schnorr commitment for the final confirmation
	SchnorrCommitments []byte
	// ElGamalPublic      []byte // curve.Point
	// // N Paillier and Pedersen N = p•q, p ≡ q ≡ 3 mod 4
	// N *saferith.Modulus
	// // S = r² mod N
	// S *saferith.Nat
	// // T = Sˡ mod N
	ElgamalKey  []byte
	PaillierKey []byte
	PedersenKey []byte
	// T *saferith.Nat
	// Decommitment = uᵢ decommitment bytes
	Decommitment hash.Decommitment
}

// StoreBroadcastMessage implements round.BroadcastRound.
//
// - verify length of Schnorr commitments
// - verify degree of VSS polynomial Fⱼ "in-the-exponent"
//   - if keygen, verify Fⱼ(0) != ∞
//   - if refresh, verify Fⱼ(0) == ∞
//
// - validate Paillier
// - validate Pedersen
// - validate commitments.
// - store ridⱼ, Cⱼ, Nⱼ, Sⱼ, Tⱼ, Fⱼ(X), Aⱼ.
func (r *round3) StoreBroadcastMessage(msg round.Message) error {
	content, err := r.validateBroadcastMessage(msg)
	if err != nil {
		return errors.WithMessage(err, "keygen.round3.StoreBroadcastMessage: failed to validate message")
	}

	// TODO verify vss polynomial
	// Save all X, VSSCommitments
	// VSSPolynomial := body.VSSPolynomial
	// check that the constant coefficient is 0
	// if refresh then the polynomial is constant
	// ecKey, err := r.ecdsa_km.GetKey(r.ID, string(r.SelfID()))
	// if err != nil {
	// 	return err
	// }
	// vssKey, err := ecKey.VSS()
	// // vssKey, err := r.vss_km.GetKey(r.ID, string(r.SelfID()))
	// if err != nil {
	// 	return err
	// }
	// exp, err := vssKey.ExponentsRaw()
	// if err != nil {
	// 	return err
	// }
	// if exp.IsConstant != VSSPolynomial.IsConstant {
	// 	// if !(r.VSSSecret.Constant().IsZero() == VSSPolynomial.IsConstant) {
	// 	return errors.New("vss polynomial has incorrect constant")
	// }
	// // check deg(Fⱼ) = t
	// if VSSPolynomial.Degree() != r.Threshold() {
	// 	return errors.New("vss polynomial has incorrect degree")
	// }
	from := msg.From

	fromOpts, err := keyopts.NewOptions().Set("id", r.ID, "partyid", string(from))
	if err != nil {
		return errors.WithMessage(err, "keygen.round3.StoreBroadcastMessage: failed to create options")
	}

	ridFrom, err := r.rid_km.ImportKey(content.RID, fromOpts)
	if err != nil {
		return err
	}

	chainKeyFrom, err := r.chainKey_km.ImportKey(content.C, fromOpts)
	if err != nil {
		return err
	}

	if _, err := r.paillier_km.ImportKey(content.PaillierKey, fromOpts); err != nil {
		return err
	}

	pedersenFrom, err := r.pedersen_km.ImportKey(content.PedersenKey, fromOpts)
	if err != nil {
		return err
	}

	if _, err := r.ecdsa_km.ImportKey(content.EcdsaKey, fromOpts); err != nil {
		return err
	}

	exponents := polynomial.NewEmptyExponent(r.Group())
	if err := exponents.UnmarshalBinary(content.VSSPolynomial); err != nil {
		return err
	}
	vssKey := vss.NewVssKey(nil, exponents)
	if _, err := r.vss_mgr.ImportSecrets(vssKey, fromOpts); err != nil {
		return err
	}

	if err := r.ecdsa_km.ImportSchnorrCommitment(content.SchnorrCommitments, fromOpts); err != nil {
		return err
	}
	schproof, err := r.ecdsa_km.GetSchnorrProof(fromOpts)
	if err != nil {
		return err
	}

	vssKeyFrom, err := r.ecdsa_km.GetVss(fromOpts)
	if err != nil {
		return err
	}
	exponentsFrom, err := vssKeyFrom.Exponents()
	if err != nil {
		return err
	}

	elgamalFrom, err := r.elgamal_km.ImportKey(content.ElgamalKey, fromOpts)
	if err != nil {
		return err
	}

	// Verify decommit
	if err := content.Decommitment.Validate(); err != nil {
		return err
	}
	cmt, err := r.commit_mgr.Get(fromOpts)
	if err != nil {
		return err
	}
	if err := r.commit_mgr.ImportDecommitment(content.Decommitment, fromOpts); err != nil {
		return err
	}

	if !r.Hash().Clone().Decommit(
		cmt.Commitment(),
		content.Decommitment,
		ridFrom,
		chainKeyFrom,
		exponentsFrom,
		elgamalFrom.PublicKey(),
		pedersenFrom.PublicKeyRaw().N(),
		pedersenFrom.PublicKeyRaw().S(),
		pedersenFrom.PublicKeyRaw().T(),
		schproof.Commitment(),
	) {
		return errors.New("failed to decommit")
	}

	// Mark the message as received
	if err := r.bcstmgr.Import(
		r.bcstmgr.NewMessage(r.ID, int(r.Number()), string(msg.From), true),
	); err != nil {
		return err
	}

	return nil
}

func (r *round3) validateBroadcastMessage(msg round.Message) (*broadcast3, error) {
	content, ok := msg.Content.(*broadcast3)
	if !ok || content == nil {
		return nil, round.ErrInvalidContent
	}
	if content.RID == nil {
		return nil, errors.New("keygen.round3.validateBroadcastMessage: RID is empty")
	}
	if content.C == nil {
		return nil, errors.New("keygen.round3.validateBroadcastMessage: C is empty")
	}
	if content.ElgamalKey == nil {
		return nil, errors.New("keygen.round3.validateBroadcastMessage: ElGamal key is nil")
	}
	if content.PaillierKey == nil {
		return nil, errors.New("keygen.round3.validateBroadcastMessage: Paillier key is nil")
	}
	if content.PedersenKey == nil {
		return nil, errors.New("keygen.round3.validateBroadcastMessage: Pedersen key is nil")
	}
	if content.EcdsaKey == nil {
		return nil, errors.New("keygen.round3.validateBroadcastMessage: ECDSA key is nil")
	}
	if content.VSSPolynomial == nil {
		return nil, errors.New("keygen.round3.validateBroadcastMessage: VSS polynomial is nil")
	}
	if content.SchnorrCommitments == nil {
		return nil, errors.New("keygen.round3.validateBroadcastMessage: Schnorr commitments is nil")
	}
	if content.Decommitment == nil {
		return nil, errors.New("keygen.round3.validateBroadcastMessage: decommitment is nil")
	}
	return content, nil
}

// VerifyMessage implements round.Round.
func (round3) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (round3) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
//
// - set rid = ⊕ⱼ ridⱼ and update hash state
// - prove Nᵢ is Blum
// - prove Pedersen parameters
// - prove Schnorr for all coefficients of fᵢ(X)
//   - if refresh skip constant coefficient
//
// - send proofs and encryption of share for Pⱼ.
func (r *round3) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Verify if all parties messages are received
	if !r.CanFinalize() {
		return nil, round.ErrNotEnoughMessages
	}

	opts, err := keyopts.NewOptions().Set("id", r.ID, "partyid", string(r.SelfID()))
	if err != nil {
		return nil, errors.WithMessage(err, "keygen.round3.Finalize: failed to create options")
	}

	rootOpts, err := keyopts.NewOptions().Set("id", r.ID, "partyid", "ROOT")
	if err != nil {
		return nil, errors.WithMessage(err, "keygen.round3.Finalize: failed to create options")
	}

	// c = ⊕ⱼ cⱼ
	// chainKey := r.PreviousChainKey
	// if chainKey == nil {
	chainKey := types.EmptyRID()
	for _, j := range r.PartyIDs() {
		partyOpts, err := keyopts.NewOptions().Set("id", r.ID, "partyid", string(j))
		if err != nil {
			return nil, errors.WithMessage(err, "keygen.round3.Finalize: failed to create options")
		}
		ck, err := r.chainKey_km.GetKey(partyOpts)
		if err != nil {
			return nil, err
		}
		chainKey.XOR(ck.Raw())
	}
	if _, err := r.chainKey_km.ImportKey(chainKey, rootOpts); err != nil {
		return nil, err
	}
	// }

	// RID = ⊕ⱼ RIDⱼ
	rid := types.EmptyRID()
	for _, j := range r.PartyIDs() {
		partyOpts, err := keyopts.NewOptions().Set("id", r.ID, "partyid", string(j))
		if err != nil {
			return nil, errors.WithMessage(err, "keygen.round3.Finalize: failed to create options")
		}
		rj, err := r.rid_km.GetKey(partyOpts)
		if err != nil {
			return nil, err
		}
		rid.XOR(rj.Raw())
	}
	if _, err := r.rid_km.ImportKey(rid, rootOpts); err != nil {
		return nil, err
	}

	// temporary hash which does not modify the state
	h := r.Hash().Clone()
	_ = h.WriteAny(rid, r.SelfID())

	// Prove N is a blum prime with zkmod
	pk, err := r.paillier_km.GetKey(opts)
	if err != nil {
		return nil, err
	}
	mod := pk.NewZKModProof(h.Clone(), r.Pool)

	// prove s, t are correct as aux parameters with zkprm
	ped, err := r.pedersen_km.GetKey(opts)
	if err != nil {
		return nil, err
	}
	prm := ped.NewProof(h.Clone(), r.Pool)

	if err := r.BroadcastMessage(out, &broadcast4{
		Mod: mod,
		Prm: prm,
	}); err != nil {
		return r, err
	}

	vssKey, err := r.vss_mgr.GetSecrets(opts)
	if err != nil {
		return nil, err
	}

	// create P2P messages with encrypted shares and zkfac proof
	for _, j := range r.OtherPartyIDs() {
		partyOpts, err := keyopts.NewOptions().Set("id", r.ID, "partyid", string(j))
		if err != nil {
			return nil, errors.WithMessage(err, "keygen.round3.Finalize: failed to create options")
		}
		pedj, err := r.pedersen_km.GetKey(partyOpts)
		if err != nil {
			return nil, err
		}
		paillierj, err := r.paillier_km.GetKey(partyOpts)
		if err != nil {
			return nil, err
		}

		fac := pk.NewZKFACProof(h.Clone(), zkfac.Public{
			N:   pk.PublicKey().ParamN(),
			Aux: pedj.PublicKeyRaw(),
		})

		// compute fᵢ(j)
		share, err := vssKey.Evaluate(j.Scalar(r.Group()))
		if err != nil {
			return nil, err
		}
		// Encrypt share
		C, _ := paillierj.Encode(curve.MakeInt(share))

		err = r.SendMessage(out, &message4{
			Share: C,
			Fac:   fac,
		}, j)
		if err != nil {
			return r, err
		}
	}

	// update last round processed in StateManager
	if err := r.statemanger.SetLastRound(r.ID, int(r.Number())); err != nil {
		return r, err
	}

	// Write rid to the hash state
	r.UpdateHashState(rid)
	return &round4{
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
	}, nil
}

func (r *round3) CanFinalize() bool {
	// Verify if all parties commitments are received
	var parties []string
	for _, p := range r.OtherPartyIDs() {
		parties = append(parties, string(p))
	}
	rcvd, err := r.bcstmgr.HasAll(r.ID, int(r.Number()), parties)
	if err != nil {
		return false
	}
	return rcvd
}

// MessageContent implements round.Round.
func (round3) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcast3) RoundNumber() round.Number { return 3 }

// BroadcastContent implements round.BroadcastRound.
func (r *round3) BroadcastContent() round.BroadcastContent {
	return &broadcast3{
		// VSSPolynomial:      polynomial.EmptyExponent(r.Group()),
		// SchnorrCommitments: r.Group().NewPoint(), //zksch.EmptyCommitment(r.Group()),
		// ElGamalPublic:      r.Group().NewPoint(),
	}
}

// Number implements round.Round.
func (round3) Number() round.Number { return 3 }
