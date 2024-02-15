package keygen

import (
	"crypto/rand"
	"encoding/json"
	"errors"

	"github.com/mr-shifu/mpc-lib/core/hash"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/math/polynomial"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
	"github.com/mr-shifu/mpc-lib/core/paillier"
	"github.com/mr-shifu/mpc-lib/core/party"
	"github.com/mr-shifu/mpc-lib/core/pedersen"
	"github.com/mr-shifu/mpc-lib/core/pool"
	zksch "github.com/mr-shifu/mpc-lib/core/zk/sch"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/lib/types"
)

var _ round.Round = (*round1)(nil)

type round1 struct {
	*round.Helper

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

	// VSSSecret = fᵢ(X)
	// Polynomial from which the new secret shares are computed.
	// Keygen:  fᵢ(0) = xⁱ
	// Refresh: fᵢ(0) = 0
	VSSSecret *polynomial.Polynomial
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
	PaillierSecret := paillier.NewSecretKey(nil)
	SelfPaillierPublic := PaillierSecret.PublicKey
	SelfPedersenPublic, PedersenSecret := PaillierSecret.GeneratePedersen()

	ElGamalSecret, ElGamalPublic := sample.ScalarPointPair(rand.Reader, r.Group())

	// save our own share already so we are consistent with what we receive from others
	SelfShare := r.VSSSecret.Evaluate(r.SelfID().Scalar(r.Group()))

	// set Fᵢ(X) = fᵢ(X)•G
	SelfVSSPolynomial := polynomial.NewPolynomialExponent(r.VSSSecret)

	// generate Schnorr randomness
	SchnorrRand := zksch.NewRandomness(rand.Reader, r.Group(), nil)

	// Sample RIDᵢ
	SelfRID, err := types.NewRID(rand.Reader)
	if err != nil {
		return r, errors.New("failed to sample Rho")
	}
	chainKey, err := types.NewRID(rand.Reader)
	if err != nil {
		return r, errors.New("failed to sample c")
	}

	// commit to data in message 2
	SelfCommitment, Decommitment, err := r.HashForID(r.SelfID()).Commit(
		SelfRID, chainKey, SelfVSSPolynomial, SchnorrRand.Commitment(), ElGamalPublic,
		SelfPedersenPublic.N(), SelfPedersenPublic.S(), SelfPedersenPublic.T())
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
		VSSPolynomials:     map[party.ID]*polynomial.Exponent{r.SelfID(): SelfVSSPolynomial},
		Commitments:        map[party.ID]hash.Commitment{r.SelfID(): SelfCommitment},
		RIDs:               map[party.ID]types.RID{r.SelfID(): SelfRID},
		ChainKeys:          map[party.ID]types.RID{r.SelfID(): chainKey},
		ShareReceived:      map[party.ID]curve.Scalar{r.SelfID(): SelfShare},
		ElGamalPublic:      map[party.ID]curve.Point{r.SelfID(): ElGamalPublic},
		PaillierPublic:     map[party.ID]*paillier.PublicKey{r.SelfID(): SelfPaillierPublic},
		Pedersen:           map[party.ID]*pedersen.Parameters{r.SelfID(): SelfPedersenPublic},
		ElGamalSecret:      ElGamalSecret,
		PaillierSecret:     PaillierSecret,
		PedersenSecret:     PedersenSecret,
		SchnorrRand:        SchnorrRand,
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

type round1Serialized struct {
	Helper                    []byte
	PreviousSecretECDSA       []byte
	PreviousPublicSharesECDSA map[party.ID][]byte
	PreviousChainKey          []byte
	VSSSecret                 []byte
}

func NewEmptyRound1(g curve.Curve, pl *pool.Pool) *round1 {
	return &round1{
		Helper:                    round.NewEmptyHelper(g, pl),
		PreviousPublicSharesECDSA: nil,
		PreviousSecretECDSA:       nil,
	}
}
func (r round1) Serialize() (ser []byte, err error) {
	rs := round1Serialized{
		PreviousPublicSharesECDSA: make(map[party.ID][]byte),
		PreviousChainKey:          []byte(r.PreviousChainKey),
	}

	rs.Helper, err = r.Helper.Serialize()
	if err != nil {
		return nil, err
	}

	if r.PreviousSecretECDSA != nil {
		rs.PreviousSecretECDSA, err = r.PreviousSecretECDSA.MarshalBinary()
		if err != nil {
			return nil, err
		}
	}

	for id, pk := range r.PreviousPublicSharesECDSA {
		rs.PreviousPublicSharesECDSA[id], err = pk.MarshalBinary()
		if err != nil {
			return nil, err
		}
	}

	rs.VSSSecret, err = r.VSSSecret.Serialize()
	if err != nil {
		return nil, err
	}

	return json.Marshal(rs)
}
func (r *round1) Deserialize(data []byte) error {
	var rs round1Serialized
	if err := json.Unmarshal(data, &rs); err != nil {
		return err
	}

	if err := r.Helper.Deserialize(rs.Helper); err != nil {
		return err
	}

	r.PreviousChainKey = rs.PreviousChainKey

	if rs.PreviousSecretECDSA != nil {
		if err := r.PreviousSecretECDSA.UnmarshalBinary(rs.PreviousSecretECDSA); err != nil {
			return err
		}
	}

	if len(rs.PreviousPublicSharesECDSA) > 0 {
		r.PreviousPublicSharesECDSA = make(map[party.ID]curve.Point)
		for id, pk := range rs.PreviousPublicSharesECDSA {
			if err := r.PreviousPublicSharesECDSA[id].UnmarshalBinary(pk); err != nil {
				return err
			}
		}
	}

	r.VSSSecret = polynomial.NewEmptyPolynomial(r.Helper.Group(), r.Helper.Threshold())
	if rs.VSSSecret != nil {
		if err := r.VSSSecret.Deserialize(rs.VSSSecret); err != nil {
			return err
		}
	}

	return nil
}

func (r *round1) Equal(other round.Round) bool {
	return true
}
