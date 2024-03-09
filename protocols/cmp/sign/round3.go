package sign

import (
	"errors"
	"fmt"

	"github.com/cronokirby/saferith"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/paillier"
	"github.com/mr-shifu/mpc-lib/core/party"
	zkaffg "github.com/mr-shifu/mpc-lib/core/zk/affg"
	zklogstar "github.com/mr-shifu/mpc-lib/core/zk/logstar"
	"github.com/mr-shifu/mpc-lib/lib/round"
	sw_ecdsa "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ecdsa"
)

var _ round.Round = (*round3)(nil)

type round3 struct {
	*round2

	// Number of Broacasted Messages received
	MessageBroadcasted map[party.ID]bool
	MessageForwarded   map[party.ID]bool
}

type message3 struct {
	DeltaD     *paillier.Ciphertext // DeltaD = Dᵢⱼ
	DeltaF     *paillier.Ciphertext // DeltaF = Fᵢⱼ
	DeltaProof *zkaffg.Proof
	ChiD       *paillier.Ciphertext // DeltaD = D̂_{ij}
	ChiF       *paillier.Ciphertext // ChiF = F̂ᵢⱼ
	ChiProof   *zkaffg.Proof
	ProofLog   *zklogstar.Proof
}

type broadcast3 struct {
	round.NormalBroadcastContent
	BigGammaShare curve.Point // BigGammaShare = Γⱼ
}

// StoreBroadcastMessage implements round.BroadcastRound.
//
// - store Γⱼ
func (r *round3) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*broadcast3)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	if body.BigGammaShare.IsIdentity() {
		return round.ErrNilFields
	}

	gamma := sw_ecdsa.NewECDSAKey(nil, body.BigGammaShare, body.BigGammaShare.Curve())
	if err := r.gamma.ImportKey(r.cfg.ID(), string(msg.From), gamma); err != nil {
		return err
	}

	// Mark the message as received
	r.MessageBroadcasted[msg.From] = true

	return nil
}

// VerifyMessage implements round.Round.
//
// - verify zkproofs affg (2x) zklog*.
func (r *round3) VerifyMessage(msg round.Message) error {
	from, to := msg.From, msg.To
	body, ok := msg.Content.(*message3)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	paillierFrom, err := r.paillier_km.GetKey(r.cfg.KeyID(), string(from))
	if err != nil {
		return err
	}
	paillierTo, err := r.paillier_km.GetKey(r.cfg.KeyID(), string(to))
	if err != nil {
		return err
	}
	pedTo, err := r.pedersen_km.GetKey(r.cfg.KeyID(), string(to))
	if err != nil {
		return err
	}

	gammaFrom, err := r.gamma.GetKey(r.cfg.ID(), string(from))
	if err != nil {
		return err
	}
	gammaFrom_pek, err := gammaFrom.GetPaillierEncodedKey()
	if err != nil {
		return err
	}

	eckeyFrom, err := r.ec.GetKey(r.cfg.ID(), string(from))
	if err != nil {
		return err
	}

	shareKTo, err := r.signK.GetKey(r.cfg.ID(), string(to))
	if err != nil {
		return err
	}
	shareKTo_pek, err := shareKTo.GetPaillierEncodedKey()
	if err != nil {
		return err
	}

	if !body.DeltaProof.Verify(r.HashForID(from), zkaffg.Public{
		Kv:       shareKTo_pek.Encoded(),
		Dv:       body.DeltaD,
		Fp:       body.DeltaF,
		Xp:       gammaFrom.PublicKeyRaw(),
		Prover:   paillierFrom.PublicKeyRaw(),
		Verifier: paillierTo.PublicKeyRaw(),
		Aux:      pedTo.PublicKeyRaw(),
	}) {
		return errors.New("failed to validate affg proof for Delta MtA")
	}

	if !body.ChiProof.Verify(r.HashForID(from), zkaffg.Public{
		Kv:       shareKTo_pek.Encoded(),
		Dv:       body.ChiD,
		Fp:       body.ChiF,
		Xp:       eckeyFrom.PublicKeyRaw(),
		Prover:   paillierFrom.PublicKeyRaw(),
		Verifier: paillierTo.PublicKeyRaw(),
		Aux:      pedTo.PublicKeyRaw(),
	}) {
		return errors.New("failed to validate affg proof for Chi MtA")
	}

	if !body.ProofLog.Verify(r.HashForID(from), zklogstar.Public{
		C:      gammaFrom_pek.Encoded(),
		X:      gammaFrom.PublicKeyRaw(),
		Prover: paillierFrom.PublicKeyRaw(),
		Aux:    pedTo.PublicKeyRaw(),
	}) {
		return errors.New("failed to validate log proof")
	}

	return nil
}

// StoreMessage implements round.Round.
//
// - Decrypt MtA shares,
// - save αᵢⱼ, α̂ᵢⱼ.
func (r *round3) StoreMessage(msg round.Message) error {
	from, body := msg.From, msg.Content.(*message3)

	// αᵢⱼ
	paillierKey, err := r.paillier_km.GetKey(r.cfg.KeyID(), string(from))
	if err != nil {
		return err
	}
	DeltaShareAlpha, err := paillierKey.Decode(body.DeltaD)
	if err != nil {
		return fmt.Errorf("failed to decrypt alpha share for delta: %w", err)
	}
	// α̂ᵢⱼ
	ChiShareAlpha, err := paillierKey.Decode(body.ChiD)
	if err != nil {
		return fmt.Errorf("failed to decrypt alpha share for chi: %w", err)
	}

	if err := r.delta_mta.SetAlpha(r.cfg.ID(), string(from), DeltaShareAlpha); err != nil {
		return err
	}
	if er := r.chi_mta.SetAlpha(r.cfg.ID(), string(from), ChiShareAlpha); er != nil {
		return nil
	}

	// Mark the message as received
	r.MessageForwarded[from] = true

	return nil
}

// Finalize implements round.Round
//
// - Γ = ∑ⱼ Γⱼ
// - Δᵢ = [kᵢ]Γ
// - δᵢ = γᵢ kᵢ + ∑ⱼ δᵢⱼ
// - χᵢ = xᵢ kᵢ + ∑ⱼ χᵢⱼ.
func (r *round3) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Verify if all parties commitments are received
	if len(r.MessageBroadcasted) != r.N()-1 || len(r.MessageForwarded) != r.N()-1 {
		return nil, round.ErrNotEnoughMessages
	}

	// Γ = ∑ⱼ Γⱼ
	Gamma := r.Group().NewPoint()
	for j := range r.PartyIDs() {
		gammaj, err := r.gamma.GetKey(r.cfg.ID(), string(j))
		if err != nil {
			return nil, err
		}
		Gamma = Gamma.Add(gammaj.PublicKeyRaw())
	}
	gammaRoot := sw_ecdsa.NewECDSAKey(nil, Gamma, Gamma.Curve())
	r.gamma.ImportKey(r.cfg.ID(), "ROOT", gammaRoot)

	// Δᵢ = [kᵢ]Γ
	KShare, err := r.signK.GetKey(r.cfg.ID(), string(r.SelfID()))
	if err != nil {
		return nil, err
	}
	bigDeltaShare := KShare.Act(Gamma, false)
	bigDelta := sw_ecdsa.NewECDSAKey(nil, bigDeltaShare, bigDeltaShare.Curve())
	if err := r.bigDelta.ImportKey(r.cfg.ID(), string(r.SelfID()), bigDelta); err != nil {
		return nil, err
	}

	// δᵢ = γᵢ kᵢ + ∑ⱼ δᵢⱼ
	delta_mta_sum := new(saferith.Int)
	for _, j := range r.OtherPartyIDs() {
		//δᵢ += αᵢⱼ + βᵢⱼ
		deltaj, err := r.delta_mta.GetKey(r.cfg.ID(), string(j))
		if err != nil {
			return nil, err
		}
		delta_mta_sum = delta_mta_sum.Add(delta_mta_sum, deltaj.Alpha(), -1)
		delta_mta_sum = delta_mta_sum.Add(delta_mta_sum, deltaj.Beta(), -1)
	}
	delta_mta_sum_scalar := r.Group().NewScalar().SetNat(delta_mta_sum.Mod(r.Group().Order()))
	gamma, err := r.gamma.GetKey(r.cfg.ID(), string(r.SelfID()))
	if err != nil {
		return nil, err
	}
	DeltaShareScalar := gamma.CommitByKey(KShare, delta_mta_sum_scalar)
	deltaShare := sw_ecdsa.NewECDSAKey(DeltaShareScalar, DeltaShareScalar.Act(DeltaShareScalar.Curve().NewBasePoint()), DeltaShareScalar.Curve())
	if err := r.delta.ImportKey(r.cfg.ID(), string(r.SelfID()), deltaShare); err != nil {
		return nil, err
	}

	// χᵢ = xᵢ kᵢ + ∑ⱼ χᵢⱼ
	chi_mta_sum := new(saferith.Int)
	for _, j := range r.OtherPartyIDs() {
		chij, err := r.chi_mta.GetKey(r.cfg.ID(), string(j))
		if err != nil {
			return nil, err
		}
		chi_mta_sum = chi_mta_sum.Add(chi_mta_sum, chij.Alpha(), -1)
		chi_mta_sum = chi_mta_sum.Add(chi_mta_sum, chij.Beta(), -1)
	}
	chi_mta_sum_scalar := r.Group().NewScalar().SetNat(chi_mta_sum.Mod(r.Group().Order()))
	eckey, err := r.ec.GetKey(r.cfg.ID(), string(r.SelfID()))
	if err != nil {
		return nil, err
	}
	ChaiShareScalar := eckey.CommitByKey(KShare, chi_mta_sum_scalar)
	chiShare := sw_ecdsa.NewECDSAKey(ChaiShareScalar, ChaiShareScalar.Act(ChaiShareScalar.Curve().NewBasePoint()), ChaiShareScalar.Curve())
	if err := r.chi.ImportKey(r.cfg.ID(), string(r.SelfID()), chiShare); err != nil {
		return nil, err
	}

	// DeltaShareScalar := r.Group().NewScalar().SetNat(DeltaShare.Mod(r.Group().Order()))
	if err := r.BroadcastMessage(out, &broadcast4{
		DeltaShare:    DeltaShareScalar,
		BigDeltaShare: bigDeltaShare,
	}); err != nil {
		return r, err
	}

	paillier, err := r.paillier_km.GetKey(r.cfg.KeyID(), string(r.SelfID()))
	if err != nil {
		return r, err
	}
	KSharePEK, err := KShare.GetPaillierEncodedKey()
	if err != nil {
		return nil, err
	}

	otherIDs := r.OtherPartyIDs()
	errs := r.Pool.Parallelize(len(otherIDs), func(i int) interface{} {
		j := otherIDs[i]

		pedj, err := r.pedersen_km.GetKey(r.cfg.KeyID(), string(j))
		if err != nil {
			return err
		}

		proofLog, err := KShare.NewZKLogstarProof(
			r.HashForID(r.SelfID()),
			KSharePEK.Encoded(),
			bigDeltaShare,
			Gamma,
			paillier.PublicKey(),
			pedj.PublicKey(),
		)
		if err != nil {
			return err
		}

		if err := r.SendMessage(out, &message4{ProofLog: proofLog}, j); err != nil {
			return err
		}
		return nil
	})
	for _, err := range errs {
		if err != nil {
			return r, err.(error)
		}
	}

	return &round4{
		round3:             r,
		MessageBroadcasted: make(map[party.ID]bool),
	}, nil
}

func (r *round3) CanFinalize() bool {
	// Verify if all parties commitments are received
	return len(r.MessageBroadcasted) == r.N()-1 && len(r.MessageForwarded) == r.N()-1
}

// RoundNumber implements round.Content.
func (message3) RoundNumber() round.Number { return 3 }

// MessageContent implements round.Round.
func (r *round3) MessageContent() round.Content {
	return &message3{
		ProofLog:   zklogstar.Empty(r.Group()),
		DeltaProof: zkaffg.Empty(r.Group()),
		ChiProof:   zkaffg.Empty(r.Group()),
	}
}

// RoundNumber implements round.Content.
func (broadcast3) RoundNumber() round.Number { return 3 }

// BroadcastContent implements round.BroadcastRound.
func (r *round3) BroadcastContent() round.BroadcastContent {
	return &broadcast3{
		BigGammaShare: r.Group().NewPoint(),
	}
}

// Number implements round.Round.
func (round3) Number() round.Number { return 3 }

func (r *round3) Equal(other round.Round) bool {
	return true
}
