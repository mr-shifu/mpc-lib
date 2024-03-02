package keygen

import (
	"errors"
	"fmt"

	"github.com/cronokirby/saferith"
	"github.com/mr-shifu/mpc-lib/core/hash"
	"github.com/mr-shifu/mpc-lib/core/math/arith"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/math/polynomial"
	"github.com/mr-shifu/mpc-lib/core/paillier"
	"github.com/mr-shifu/mpc-lib/core/party"
	"github.com/mr-shifu/mpc-lib/core/pedersen"
	zkfac "github.com/mr-shifu/mpc-lib/core/zk/fac"
	zksch "github.com/mr-shifu/mpc-lib/core/zk/sch"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/lib/types"
	sw_ecdsa "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ecdsa"
	sw_paillier "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillier"
	sw_pedersen "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/pedersen"
	comm_ecdsa "github.com/mr-shifu/mpc-lib/pkg/mpc/common/ecdsa"
	comm_elgamal "github.com/mr-shifu/mpc-lib/pkg/mpc/common/elgamal"
	comm_mpc_ks "github.com/mr-shifu/mpc-lib/pkg/mpc/common/mpckey"
	comm_paillier "github.com/mr-shifu/mpc-lib/pkg/mpc/common/paillier"
	comm_pedersen "github.com/mr-shifu/mpc-lib/pkg/mpc/common/pedersen"
	comm_rid "github.com/mr-shifu/mpc-lib/pkg/mpc/common/rid"
)

var _ round.Round = (*round3)(nil)

type round3 struct {
	*round2

	mpc_ks      comm_mpc_ks.MPCKeystore
	elgamal_km  comm_elgamal.ElgamalKeyManager
	paillier_km comm_paillier.PaillierKeyManager
	pedersen_km comm_pedersen.PedersenKeyManager
	ecdsa_km    comm_ecdsa.ECDSAKeyManager
	rid_km      comm_rid.RIDKeyManager
	chainKey_km comm_rid.RIDKeyManager

	// SchnorrCommitments[j] = Aⱼ
	// Commitment for proof of knowledge in the last round
	SchnorrCommitments map[party.ID]*zksch.Commitment // Aⱼ

	// Number of Broacasted Messages received
	MessageBroadcasted map[party.ID]bool
}

type broadcast3 struct {
	round.NormalBroadcastContent
	// RID = RIDᵢ
	RID types.RID
	C   types.RID
	// VSSPolynomial = Fᵢ(X) VSSPolynomial
	VSSPolynomial *polynomial.Exponent
	// SchnorrCommitments = Aᵢ Schnorr commitment for the final confirmation
	SchnorrCommitments curve.Point
	ElGamalPublic      []byte // curve.Point
	// N Paillier and Pedersen N = p•q, p ≡ q ≡ 3 mod 4
	N *saferith.Modulus
	// S = r² mod N
	S *saferith.Nat
	// T = Sˡ mod N
	T *saferith.Nat
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
	from := msg.From
	body, ok := msg.Content.(*broadcast3)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	// check nil
	if body.N == nil || body.S == nil || body.T == nil || body.VSSPolynomial == nil || body.SchnorrCommitments == nil {
		return round.ErrNilFields
	}
	// check RID length
	if err := body.RID.Validate(); err != nil {
		return fmt.Errorf("rid: %w", err)
	}
	if err := body.C.Validate(); err != nil {
		return fmt.Errorf("chainkey: %w", err)
	}
	// check decommitment
	if err := body.Decommitment.Validate(); err != nil {
		return err
	}

	// Save all X, VSSCommitments
	VSSPolynomial := body.VSSPolynomial
	// check that the constant coefficient is 0
	// if refresh then the polynomial is constant
	ecKey, err := r.ecdsa_km.GetKey(r.KeyID, string(r.SelfID()))
	if err != nil {
		return err
	}
	vssKey, err := ecKey.VSS()
	// vssKey, err := r.vss_km.GetKey(r.KeyID, string(r.SelfID()))
	if err != nil {
		return err
	}
	exp, err := vssKey.ExponentsRaw()
	if err != nil {
		return err
	}
	if exp.IsConstant != VSSPolynomial.IsConstant {
		// if !(r.VSSSecret.Constant().IsZero() == VSSPolynomial.IsConstant) {
		return errors.New("vss polynomial has incorrect constant")
	}
	// check deg(Fⱼ) = t
	if VSSPolynomial.Degree() != r.Threshold() {
		return errors.New("vss polynomial has incorrect degree")
	}

	// Set Paillier
	if err := paillier.ValidateN(body.N); err != nil {
		return err
	}

	// Verify Pedersen
	if err := pedersen.ValidateParameters(body.N, body.S, body.T); err != nil {
		return err
	}
	// Verify decommit
	if !r.HashForID(from).Decommit(r.Commitments[from], body.Decommitment,
		body.RID, body.C, VSSPolynomial, body.SchnorrCommitments, body.ElGamalPublic, body.N, body.S, body.T) {
		// return errors.New("failed to decommit")
	}

	r.rid_km.ImportKey(r.KeyID, string(from), body.RID)

	r.chainKey_km.ImportKey(r.KeyID, string(from), body.C)

	paillierKey := sw_paillier.NewPaillierKey(nil, paillier.NewPublicKey(body.N))
	paillier_byte, err := paillierKey.Bytes()
	if err != nil {
		return err
	}
	if _, err := r.paillier_km.ImportKey(r.KeyID, string(from), paillier_byte); err != nil {
		return err
	}

	ped := sw_pedersen.NewPedersenKey(nil, pedersen.New(arith.ModulusFromN(body.N), body.S, body.T))
	ped_byte, err := ped.Bytes()
	if err != nil {
		return err
	}
	if _, err := r.pedersen_km.ImportKey(r.KeyID, string(from), ped_byte); err != nil {
		return err
	}

	vss_bytes, err := body.VSSPolynomial.MarshalBinary()
	if err != nil {
		return err
	}
	pub := body.VSSPolynomial.Constant()
	k := sw_ecdsa.NewECDSAKey(nil, pub, pub.Curve())
	err = r.ecdsa_km.ImportKey(r.KeyID, string(from), k)
	if err != nil {
		return err
	}
	fromKey, err := r.ecdsa_km.GetKey(r.KeyID, string(from))
	if err != nil {
		return err
	}
	if err := fromKey.ImportVSSSecrets(vss_bytes); err != nil {
		return err
	}
	if err := fromKey.ImportVSSSecrets(vss_bytes); err != nil {
		return err
	}

	// r.SchnorrCommitments[from] = body.SchnorrCommitments
	if err := fromKey.ImportSchnorrCommitment(body.SchnorrCommitments); err != nil {
		return err
	}

	if _, err := r.elgamal_km.ImportKey(r.KeyID, string(from), body.ElGamalPublic); err != nil {
		return err
	}

	// Mark the message as received
	r.MessageBroadcasted[from] = true

	return nil
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
	if len(r.MessageBroadcasted) != r.N()-1 {
		return nil, round.ErrNotEnoughMessages
	}

	mpckey, err := r.mpc_ks.Get(r.KeyID)
	if err != nil {
		return nil, err
	}

	// c = ⊕ⱼ cⱼ
	chainKey := r.PreviousChainKey
	if chainKey == nil {
		chainKey = types.EmptyRID()
		for _, j := range r.PartyIDs() {
			ck, err := r.chainKey_km.GetKey(r.KeyID, string(j))
			if err != nil {
				return nil, err
			}
			chainKey.XOR(ck.Raw())
		}
	}

	// RID = ⊕ⱼ RIDⱼ
	rid := types.EmptyRID()
	for _, j := range r.PartyIDs() {
		rj, err := r.rid_km.GetKey(r.KeyID, string(j))
		if err != nil {
			return nil, err
		}
		rid.XOR(rj.Raw())
	}

	mpckey.ChainKey = chainKey
	mpckey.RID = rid
	if err := r.mpc_ks.Update(mpckey); err != nil {
		return nil, err
	}

	// temporary hash which does not modify the state
	h := r.Hash().Clone()
	_ = h.WriteAny(rid, r.SelfID())

	// Prove N is a blum prime with zkmod
	// mod := zkmod.NewProof(h.Clone(), zkmod.Private{
	// 	P:   r.PaillierSecret.P(),
	// 	Q:   r.PaillierSecret.Q(),
	// 	Phi: r.PaillierSecret.Phi(),
	// }, zkmod.Public{N: r.PaillierPublic[r.SelfID()].N()}, r.Pool)
	pk, err := r.paillier_km.GetKey(r.KeyID, string(r.SelfID()))
	if err != nil {
		return nil, err
	}
	mod := pk.NewZKModProof(h.Clone(), r.Pool)

	// prove s, t are correct as aux parameters with zkprm
	// prm := zkprm.NewProof(zkprm.Private{
	// 	Lambda: r.PedersenSecret,
	// 	Phi:    r.PaillierSecret.Phi(),
	// 	P:      r.PaillierSecret.P(),
	// 	Q:      r.PaillierSecret.Q(),
	// }, h.Clone(), zkprm.Public{Aux: r.Pedersen[r.SelfID()]}, r.Pool)
	ped, err := r.pedersen_km.GetKey(r.KeyID, string(r.SelfID()))
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

	vssKey, err := r.ecdsa_km.GetVSSKey(r.KeyID, string(r.SelfID()))
	if err != nil {
		return nil, err
	}

	// create P2P messages with encrypted shares and zkfac proof
	for _, j := range r.OtherPartyIDs() {
		pedj, err := r.pedersen_km.GetKey(r.KeyID, string(j))
		if err != nil {
			return nil, err
		}
		paillierj, err := r.paillier_km.GetKey(r.KeyID, string(j))
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

	// Write rid to the hash state
	r.UpdateHashState(rid)
	return &round4{
		round3:             r,
		mpc_ks:             r.mpc_ks,
		elgamal_km:         r.elgamal_km,
		paillier_km:        r.paillier_km,
		pedersen_km:        r.pedersen_km,
		ecdsa_km:           r.ecdsa_km,
		rid_km:             r.rid_km,
		chainKey_km:        r.chainKey_km,
		MessageBroadcasted: make(map[party.ID]bool),
		MessagesForwarded:  make(map[party.ID]bool),
	}, nil
}

func (r *round3) CanFinalize() bool {
	// Verify if all parties commitments are received
	return len(r.MessageBroadcasted) == r.N()-1
}

// MessageContent implements round.Round.
func (round3) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcast3) RoundNumber() round.Number { return 3 }

// BroadcastContent implements round.BroadcastRound.
func (r *round3) BroadcastContent() round.BroadcastContent {
	return &broadcast3{
		VSSPolynomial:      polynomial.EmptyExponent(r.Group()),
		SchnorrCommitments: r.Group().NewPoint(), //zksch.EmptyCommitment(r.Group()),
		// ElGamalPublic:      r.Group().NewPoint(),
	}
}

// Number implements round.Round.
func (round3) Number() round.Number { return 3 }
