package keygen

import (
	"bytes"
	"encoding/json"

	"github.com/cronokirby/saferith"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/lib/types"
	"github.com/mr-shifu/mpc-lib/pkg/hash"
	"github.com/mr-shifu/mpc-lib/pkg/math/curve"
	"github.com/mr-shifu/mpc-lib/pkg/math/polynomial"
	"github.com/mr-shifu/mpc-lib/pkg/paillier"
	"github.com/mr-shifu/mpc-lib/pkg/party"
	"github.com/mr-shifu/mpc-lib/pkg/pedersen"
	"github.com/mr-shifu/mpc-lib/pkg/pool"
	zkmod "github.com/mr-shifu/mpc-lib/pkg/zk/mod"
	zksch "github.com/mr-shifu/mpc-lib/pkg/zk/sch"
)

var _ round.Round = (*round2)(nil)

type round2 struct {
	*round1

	// VSSPolynomials[j] = Fⱼ(X) = fⱼ(X)•G
	VSSPolynomials map[party.ID]*polynomial.Exponent

	// Commitments[j] = H(Keygen3ⱼ ∥ Decommitments[j])
	Commitments map[party.ID]hash.Commitment

	// RIDs[j] = ridⱼ
	RIDs map[party.ID]types.RID
	// ChainKeys[j] = cⱼ
	ChainKeys map[party.ID]types.RID

	// ShareReceived[j] = xʲᵢ
	// share received from party j
	ShareReceived map[party.ID]curve.Scalar

	ElGamalPublic map[party.ID]curve.Point
	// PaillierPublic[j] = Nⱼ
	PaillierPublic map[party.ID]*paillier.PublicKey

	// Pedersen[j] = (Nⱼ,Sⱼ,Tⱼ)
	Pedersen map[party.ID]*pedersen.Parameters

	ElGamalSecret curve.Scalar

	// PaillierSecret = (pᵢ, qᵢ)
	PaillierSecret *paillier.SecretKey

	// PedersenSecret = λᵢ
	// Used to generate the Pedersen parameters
	PedersenSecret *saferith.Nat

	// SchnorrRand = aᵢ
	// Randomness used to compute Schnorr commitment of proof of knowledge of secret share
	SchnorrRand *zksch.Randomness

	// Decommitment for Keygen3ᵢ
	Decommitment hash.Decommitment // uᵢ

	// Number of Broacasted Messages received
	MessageBroadcasted map[party.ID]bool
}

type broadcast2 struct {
	round.ReliableBroadcastContent
	// Commitment = Vᵢ = H(ρᵢ, Fᵢ(X), Aᵢ, Yᵢ, Nᵢ, sᵢ, tᵢ, uᵢ)
	Commitment hash.Commitment
}

// StoreBroadcastMessage implements round.BroadcastRound.
// - save commitment Vⱼ.
func (r *round2) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*broadcast2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	if err := body.Commitment.Validate(); err != nil {
		return err
	}
	r.Commitments[msg.From] = body.Commitment
	// Mark the message as received
	r.MessageBroadcasted[msg.From] = true

	return nil
}

// VerifyMessage implements round.Round.
func (round2) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (round2) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
//
// - send all committed data.
func (r *round2) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Verify if all parties commitments are received
	if len(r.MessageBroadcasted) != r.N()-1 {
		return nil, round.ErrNotEnoughMessages
	}

	// Send the message we created in Round1 to all
	err := r.BroadcastMessage(out, &broadcast3{
		RID:                r.RIDs[r.SelfID()],
		C:                  r.ChainKeys[r.SelfID()],
		VSSPolynomial:      r.VSSPolynomials[r.SelfID()],
		SchnorrCommitments: r.SchnorrRand.Commitment(),
		ElGamalPublic:      r.ElGamalPublic[r.SelfID()],
		N:                  r.Pedersen[r.SelfID()].N(),
		S:                  r.Pedersen[r.SelfID()].S(),
		T:                  r.Pedersen[r.SelfID()].T(),
		Decommitment:       r.Decommitment,
	})
	if err != nil {
		return r, err
	}
	return &round3{
		round2:             r,
		SchnorrCommitments: map[party.ID]*zksch.Commitment{},
		MessageBroadcasted: make(map[party.ID]bool),
	}, nil
}

func (r *round2) CanFinalize() bool {
	// Verify if all parties commitments are received
	return len(r.MessageBroadcasted) == r.N()-1
}

// PreviousRound implements round.Round.
func (r *round2) PreviousRound() round.Round { return r.round1 }

// MessageContent implements round.Round.
func (round2) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcast2) RoundNumber() round.Number { return 2 }

// BroadcastContent implements round.BroadcastRound.
func (round2) BroadcastContent() round.BroadcastContent { return &broadcast2{} }

// Number implements round.Round.
func (round2) Number() round.Number { return 2 }

type round2Serialized struct {
	Round1 []byte

	VSSPolynomials map[party.ID][]byte

	Commitments map[party.ID]hash.Commitment

	RIDs map[party.ID]types.RID

	ChainKeys map[party.ID]types.RID

	ShareReceived map[party.ID][]byte

	ElGamalPublic map[party.ID][]byte

	PaillierPublic map[party.ID][]byte

	Pedersen map[party.ID][]byte

	ElGamalSecret []byte

	PaillierSecret []byte

	PedersenSecret []byte

	SchnorrRand []byte

	Decommitment hash.Decommitment

	MessageBroadcasted map[party.ID]bool
}

func NewEmptyRound2(g curve.Curve, pl *pool.Pool) *round2 {
	var r round2
	r.round1 = NewEmptyRound1(g, pl)
	r.VSSPolynomials = make(map[party.ID]*polynomial.Exponent)
	r.ShareReceived = make(map[party.ID]curve.Scalar)
	r.ElGamalPublic = make(map[party.ID]curve.Point)
	r.PaillierPublic = make(map[party.ID]*paillier.PublicKey)
	r.Pedersen = make(map[party.ID]*pedersen.Parameters)
	return &r
}

func (r *round2) Serialize() (rss []byte, err error) {
	rs := round2Serialized{
		Commitments:        r.Commitments,
		RIDs:               r.RIDs,
		ChainKeys:          r.ChainKeys,
		VSSPolynomials:     make(map[party.ID][]byte),
		ShareReceived:      make(map[party.ID][]byte),
		ElGamalPublic:      make(map[party.ID][]byte),
		PaillierPublic:     make(map[party.ID][]byte),
		Pedersen:           make(map[party.ID][]byte),
		ElGamalSecret:      nil,
		Decommitment:       r.Decommitment,
		MessageBroadcasted: r.MessageBroadcasted,
	}

	rs.Round1, err = r.round1.Serialize()
	if err != nil {
		return nil, err
	}

	for id, poly := range r.VSSPolynomials {
		rs.VSSPolynomials[id], err = poly.MarshalBinary()
		if err != nil {
			return nil, err
		}
	}

	for id, share := range r.ShareReceived {
		rs.ShareReceived[id], err = share.MarshalBinary()
		if err != nil {
			return nil, err
		}
	}

	for id, ep := range r.ElGamalPublic {
		rs.ElGamalPublic[id], err = ep.MarshalBinary()
		if err != nil {
			return nil, err
		}
	}

	for id, pp := range r.PaillierPublic {
		rs.PaillierPublic[id], err = pp.Serialize()
		if err != nil {
			return nil, err
		}
	}

	for id, p := range r.Pedersen {
		rs.Pedersen[id], err = p.Serialize()
		if err != nil {
			return nil, err
		}
	}

	rs.ElGamalSecret, err = r.ElGamalSecret.MarshalBinary()
	if err != nil {
		return nil, err
	}

	rs.PaillierSecret, err = r.PaillierSecret.Serialize()
	if err != nil {
		return nil, err
	}

	rs.PedersenSecret, err = r.PedersenSecret.MarshalBinary()
	if err != nil {
		return nil, err
	}

	rs.SchnorrRand, err = r.SchnorrRand.Serialize()
	if err != nil {
		return nil, err
	}

	return json.Marshal(rs)
}

func (r *round2) Deserialize(data []byte) (err error) {
	var rs round2Serialized
	if err := json.Unmarshal(data, &rs); err != nil {
		return err
	}

	r.Commitments = rs.Commitments
	r.RIDs = rs.RIDs
	r.ChainKeys = rs.ChainKeys
	r.MessageBroadcasted = rs.MessageBroadcasted
	r.Decommitment = rs.Decommitment

	if err := r.round1.Deserialize(rs.Round1); err != nil {
		return err
	}

	for id, poly := range rs.VSSPolynomials {
		rpoly := polynomial.NewEmptyExponent(r.Helper.Group())
		if err := rpoly.UnmarshalBinary(poly); err != nil {
			return err
		}
		r.VSSPolynomials[id] = rpoly
	}

	for id, share := range rs.ShareReceived {
		rshare := curve.Secp256k1Scalar{}
		if err := rshare.UnmarshalBinary(share); err != nil {
			return err
		}
		r.ShareReceived[id] = &rshare
	}

	for id, ep := range rs.ElGamalPublic {
		rep := curve.Secp256k1Point{}
		if err := rep.UnmarshalBinary(ep); err != nil {
			return err
		}
		r.ElGamalPublic[id] = &rep
	}

	for id, pp := range rs.PaillierPublic {
		var paillierPubKey paillier.PublicKey
		if err := paillierPubKey.Deserialize(pp); err != nil {
			return err
		}
		r.PaillierPublic[id] = &paillierPubKey
	}

	for id, p := range rs.Pedersen {
		var pedersen pedersen.Parameters
		if err := pedersen.Deserialize(p); err != nil {
			return err
		}
		r.Pedersen[id] = &pedersen
	}

	es := curve.Secp256k1Scalar{}
	if err := es.UnmarshalBinary(rs.ElGamalSecret); err != nil {
		return err
	}
	r.ElGamalSecret = &es

	var paillierSecret paillier.SecretKey
	if err := paillierSecret.Deserialize(rs.PaillierSecret); err != nil {
		return err
	}
	r.PaillierSecret = &paillierSecret

	pedersenSecret := saferith.Nat{}
	if err := pedersenSecret.UnmarshalBinary(rs.PedersenSecret); err != nil {
		return err
	}
	r.PedersenSecret = &pedersenSecret

	schnorRand := zksch.Randomness{}
	if err := schnorRand.Deserialize(rs.SchnorrRand); err != nil {
		return err
	}
	r.SchnorrRand = &schnorRand

	return nil
}

func (r *round2) Equal(rr round.Round) bool {
	rn := rr.(*round2)

	commitment, decommitment, err := r.HashForID(r.SelfID()).Commit(
		r.RIDs[r.SelfID()],
		r.ChainKeys[r.SelfID()],
		r.VSSPolynomials[r.SelfID()],
		r.SchnorrRand.Commitment(),
		r.ElGamalPublic[r.SelfID()],
		r.Pedersen[r.SelfID()].N(),
		r.Pedersen[r.SelfID()].S(),
		r.Pedersen[r.SelfID()].T(),
	)
	if err != nil {
		return false
	}

	verified := rn.HashForID(rn.SelfID()).Decommit(
		commitment,
		decommitment,
		rn.RIDs[r.SelfID()],
		rn.ChainKeys[rn.SelfID()],
		rn.VSSPolynomials[rn.SelfID()],
		rn.SchnorrRand.Commitment(),
		rn.ElGamalPublic[rn.SelfID()],
		rn.Pedersen[rn.SelfID()].N(),
		rn.Pedersen[rn.SelfID()].S(),
		rn.Pedersen[rn.SelfID()].T(),
	)
	if !verified {
		return false
	}

	mod := zkmod.NewProof(r.Hash().Clone(), zkmod.Private{
		P:   r.PaillierSecret.P(),
		Q:   r.PaillierSecret.Q(),
		Phi: r.PaillierSecret.Phi(),
	}, zkmod.Public{N: r.PaillierPublic[r.SelfID()].N()}, r.Pool)
	if mod.Verify(zkmod.Public{N: rn.Pedersen[r.SelfID()].N()}, rn.HashForID(r.SelfID()), r.Pool) {
		return false
	}

	if !rn.round1.Equal(r.round1) {
		return false
	}
	if len(r.VSSPolynomials) != len(rn.VSSPolynomials) {
		return false
	}
	for id, poly := range r.VSSPolynomials {
		if !poly.Equal(*r.VSSPolynomials[id]) {
			return false
		}
	}
	if len(r.Commitments) != len(rn.Commitments) {
		return false
	}
	for id, commitment := range r.Commitments {
		if !bytes.Equal(commitment, rn.Commitments[id]) {
			return false
		}
	}
	if len(r.RIDs) != len(rn.RIDs) {
		return false
	}
	for id, rid := range r.RIDs {
		if !bytes.Equal(rid, rn.RIDs[id]) {
			return false
		}
	}
	if len(r.ChainKeys) != len(rn.ChainKeys) {
		return false
	}
	for id, chainKey := range r.ChainKeys {
		if !bytes.Equal(chainKey, rn.ChainKeys[id]) {
			return false
		}
	}
	if len(r.ShareReceived) != len(rn.ShareReceived) {
		return false
	}
	for id, share := range r.ShareReceived {
		if !share.Equal(rn.ShareReceived[id]) {
			return false
		}
	}
	if len(r.ElGamalPublic) != len(rn.ElGamalPublic) {
		return false
	}
	for id, ep := range r.ElGamalPublic {
		if !ep.Equal(rn.ElGamalPublic[id]) {
			return false
		}
	}
	if len(r.PaillierPublic) != len(rn.PaillierPublic) {
		return false
	}
	for id, pp := range r.PaillierPublic {
		if !pp.Equal(rn.PaillierPublic[id]) {
			return false
		}
	}
	if len(r.Pedersen) != len(rn.Pedersen) {
		return false
	}
	// for id, p := range r.Pedersen {
	// 	if !p.Equal(rn.Pedersen[id]) {
	// 		return false
	// 	}
	// }
	if !r.ElGamalSecret.Equal(rn.ElGamalSecret) {
		return false
	}
	// if !r.PaillierSecret.Equal(rn.PaillierSecret) {
	// 	return false
	// }
	// if !r.PedersenSecret.Equal(rn.PedersenSecret) {
	// 	return false
	// }
	if !bytes.Equal(r.Decommitment, rn.Decommitment) {
		return false
	}

	return true
}
