package presign

import (
	"github.com/cronokirby/saferith"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/pkg/elgamal"
	"github.com/mr-shifu/mpc-lib/pkg/math/curve"
	"github.com/mr-shifu/mpc-lib/pkg/party"
	zklogstar "github.com/mr-shifu/mpc-lib/pkg/zk/logstar"
)

var _ round.Round = (*presign4)(nil)

type presign4 struct {
	*presign3

	// DeltaShareAlpha[j] = αᵢⱼ
	DeltaShareAlpha map[party.ID]*saferith.Int
	// ChiShareAlpha[j] = α̂ᵢⱼ
	ChiShareAlpha map[party.ID]*saferith.Int

	// ElGamalChiNonce = b̂ᵢ
	ElGamalChiNonce elgamal.Nonce
	// ElGamalChi[j] = Ẑⱼ = (b̂ⱼ, χⱼ⋅G+b̂ⱼ⋅Yⱼ)
	ElGamalChi map[party.ID]*elgamal.Ciphertext

	// DeltaShares[j] = δⱼ
	DeltaShares map[party.ID]curve.Scalar

	// ChiShare = χᵢ
	ChiShare curve.Scalar

	// Number of Broacasted Messages received
	MessageBroadcasted map[party.ID]bool
}

type broadcast4 struct {
	round.NormalBroadcastContent
	// DeltaShare = δⱼ
	DeltaShare curve.Scalar
	// ElGamalChi = Ẑᵢ = (b̂ᵢ, χᵢ⋅G+b̂ᵢ⋅Yᵢ)
	ElGamalChi *elgamal.Ciphertext
}

// StoreBroadcastMessage implements round.BroadcastRound.
//
// - store Ẑⱼ, δⱼ.
func (r *presign4) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*broadcast4)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if body.DeltaShare.IsZero() || !body.ElGamalChi.Valid() {
		return round.ErrNilFields
	}
	r.ElGamalChi[msg.From] = body.ElGamalChi
	r.DeltaShares[msg.From] = body.DeltaShare

	// Mark message as received
	r.MessageBroadcasted[msg.From] = true

	return nil
}

// VerifyMessage implements round.Round.
func (presign4) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (presign4) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
//
// - set Γᵢ = γᵢ⋅G.
// - prove zklogstar.
func (r *presign4) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Verify if all parties commitments are received
	if len(r.MessageBroadcasted) != r.N()-1 {
		return nil, round.ErrNotEnoughMessages
	}

	// Γᵢ = γᵢ⋅G
	BigGammaShare := r.Group().NewScalar().SetNat(r.GammaShare.Mod(r.Group().Order())).ActOnBase()

	zkPrivate := zklogstar.Private{
		X:   r.GammaShare,
		Rho: r.GNonce,
	}

	if err := r.BroadcastMessage(out, &broadcast5{BigGammaShare: BigGammaShare}); err != nil {
		return r, err
	}

	otherIDs := r.OtherPartyIDs()
	errors := r.Pool.Parallelize(len(otherIDs), func(i int) interface{} {
		j := otherIDs[i]

		proofLog := zklogstar.NewProof(r.Group(), r.HashForID(r.SelfID()), zklogstar.Public{
			C:      r.G[r.SelfID()],
			X:      BigGammaShare,
			Prover: r.Paillier[r.SelfID()],
			Aux:    r.Pedersen[j],
		}, zkPrivate)

		err := r.SendMessage(out, &message5{
			ProofLog: proofLog,
		}, j)
		if err != nil {
			return err
		}

		return nil
	})
	for _, err := range errors {
		if err != nil {
			return r, err.(error)
		}
	}

	return &presign5{
		presign4:           r,
		BigGammaShare:      map[party.ID]curve.Point{r.SelfID(): BigGammaShare},
		MessageBroadcasted: make(map[party.ID]bool),
	}, nil
}

func (r *presign4) CanFinalize() bool {
	// Verify if all parties commitments are received
	return len(r.MessageBroadcasted) == r.N()-1
}

// MessageContent implements round.Round.
func (r *presign4) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcast4) RoundNumber() round.Number { return 4 }

// BroadcastContent implements round.BroadcastRound.
func (r *presign4) BroadcastContent() round.BroadcastContent {
	return &broadcast4{
		DeltaShare: r.Group().NewScalar(),
		ElGamalChi: elgamal.Empty(r.Group()),
	}
}

// Number implements round.Round.
func (presign4) Number() round.Number { return 4 }
