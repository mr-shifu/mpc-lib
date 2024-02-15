package keygen

import (
	"encoding/json"
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
	"github.com/mr-shifu/mpc-lib/core/pool"
	zkfac "github.com/mr-shifu/mpc-lib/core/zk/fac"
	zkmod "github.com/mr-shifu/mpc-lib/core/zk/mod"
	zkprm "github.com/mr-shifu/mpc-lib/core/zk/prm"
	zksch "github.com/mr-shifu/mpc-lib/core/zk/sch"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/lib/types"
)

var _ round.Round = (*round3)(nil)

type round3 struct {
	*round2
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
	SchnorrCommitments *zksch.Commitment
	ElGamalPublic      curve.Point
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
	if !(r.VSSSecret.Constant().IsZero() == VSSPolynomial.IsConstant) {
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
		return errors.New("failed to decommit")
	}
	r.RIDs[from] = body.RID
	r.ChainKeys[from] = body.C
	r.PaillierPublic[from] = paillier.NewPublicKey(body.N)
	r.Pedersen[from] = pedersen.New(arith.ModulusFromN(body.N), body.S, body.T)
	r.VSSPolynomials[from] = body.VSSPolynomial
	r.SchnorrCommitments[from] = body.SchnorrCommitments
	r.ElGamalPublic[from] = body.ElGamalPublic

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

	// c = ⊕ⱼ cⱼ
	chainKey := r.PreviousChainKey
	if chainKey == nil {
		chainKey = types.EmptyRID()
		for _, j := range r.PartyIDs() {
			chainKey.XOR(r.ChainKeys[j])
		}
	}

	// RID = ⊕ⱼ RIDⱼ
	rid := types.EmptyRID()
	for _, j := range r.PartyIDs() {
		rid.XOR(r.RIDs[j])
	}

	// temporary hash which does not modify the state
	h := r.Hash()
	_ = h.WriteAny(rid, r.SelfID())

	// Prove N is a blum prime with zkmod
	mod := zkmod.NewProof(h.Clone(), zkmod.Private{
		P:   r.PaillierSecret.P(),
		Q:   r.PaillierSecret.Q(),
		Phi: r.PaillierSecret.Phi(),
	}, zkmod.Public{N: r.PaillierPublic[r.SelfID()].N()}, r.Pool)

	// prove s, t are correct as aux parameters with zkprm
	prm := zkprm.NewProof(zkprm.Private{
		Lambda: r.PedersenSecret,
		Phi:    r.PaillierSecret.Phi(),
		P:      r.PaillierSecret.P(),
		Q:      r.PaillierSecret.Q(),
	}, h.Clone(), zkprm.Public{Aux: r.Pedersen[r.SelfID()]}, r.Pool)

	if err := r.BroadcastMessage(out, &broadcast4{
		Mod: mod,
		Prm: prm,
	}); err != nil {
		return r, err
	}

	// create P2P messages with encrypted shares and zkfac proof
	for _, j := range r.OtherPartyIDs() {

		// Prove that the factors of N are relatively large
		fac := zkfac.NewProof(zkfac.Private{P: r.PaillierSecret.P(), Q: r.PaillierSecret.Q()}, h.Clone(), zkfac.Public{
			N:   r.PaillierPublic[r.SelfID()].N(),
			Aux: r.Pedersen[j],
		})

		// compute fᵢ(j)
		share := r.VSSSecret.Evaluate(j.Scalar(r.Group()))
		// Encrypt share
		C, _ := r.PaillierPublic[j].Enc(curve.MakeInt(share))

		err := r.SendMessage(out, &message4{
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
		RID:                rid,
		ChainKey:           chainKey,
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
		SchnorrCommitments: zksch.EmptyCommitment(r.Group()),
		ElGamalPublic:      r.Group().NewPoint(),
	}
}

// Number implements round.Round.
func (round3) Number() round.Number { return 3 }

type round3Serialized struct {
	Round2             []byte
	SchnorrCommitments map[party.ID][]byte // Aⱼ
	MessageBroadcasted map[party.ID]bool
}

func NewEmptyRound3(g curve.Curve, pl *pool.Pool) *round3 {
	return &round3{
		round2:             NewEmptyRound2(g, pl),
		SchnorrCommitments: make(map[party.ID]*zksch.Commitment),
		MessageBroadcasted: make(map[party.ID]bool),
	}

}
func (r *round3) Serialize() (ser []byte, err error) {
	rs := round3Serialized{
		SchnorrCommitments: make(map[party.ID][]byte),
		MessageBroadcasted: r.MessageBroadcasted,
	}

	rs.Round2, err = r.round2.Serialize()
	if err != nil {
		return nil, err
	}

	for id, commitment := range r.SchnorrCommitments {
		cmts, err := commitment.Serialize()
		if err != nil {
			return nil, err
		}
		rs.SchnorrCommitments[id] = cmts
	}

	return json.Marshal(rs)
}
func (r *round3) Deserialize(data []byte) error {
	var rs round3Serialized
	if err := json.Unmarshal(data, &rs); err != nil {
		return err
	}

	if err := r.round2.Deserialize(rs.Round2); err != nil {
		return err
	}

	for id, commitment := range rs.SchnorrCommitments {
		r.SchnorrCommitments[id] = zksch.EmptyCommitment(r.Group())
		if err := r.SchnorrCommitments[id].Deserialize(commitment); err != nil {
			return err
		}
	}

	r.MessageBroadcasted = rs.MessageBroadcasted

	return nil
}
func (r *round3) Equal(other round.Round) bool {
	rr := other.(*round3)

	if !r.round2.Equal(rr.round2) {
		return false
	}

	for id, commitment := range r.SchnorrCommitments {
		if !commitment.C.Equal(rr.SchnorrCommitments[id].C) {
			return false
		}
	}

	return true
}
