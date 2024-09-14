package sign

import (
	"fmt"

	"github.com/cronokirby/saferith"
	"github.com/mr-shifu/mpc-lib/core/paillier"
	zkaffg "github.com/mr-shifu/mpc-lib/core/zk/affg"
	zklogstar "github.com/mr-shifu/mpc-lib/core/zk/logstar"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/pkg/errors"
)

var _ round.Round = (*round3)(nil)

type round3 struct {
	*round2
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
	BigGammaShare []byte
}

// StoreBroadcastMessage implements round.BroadcastRound.
//
// - store Γⱼ
func (r *round3) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*broadcast3)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	// if body.BigGammaShare.IsIdentity() {
	// 	return round.ErrNilFields
	// }

	soptsFrom, err := keyopts.NewOptions().Set("id", r.cfg.ID(), "partyid", string(msg.From))
	if err != nil {
		return errors.WithMessage(err, "sign.round3.StoreBroadcastMessage: failed to create options")
	}

	// gamma := ecdsa.NewECDSAKey(nil, body.BigGammaShare, body.BigGammaShare.Curve())
	if _, err := r.gamma.ImportKey(body.BigGammaShare, soptsFrom); err != nil {
		return err
	}

	// Mark the message as received
	if err := r.bcstmgr.Import(
		r.bcstmgr.NewMessage(r.cfg.ID(), int(r.Number()), string(msg.From), true),
	); err != nil {
		return err
	}

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

	koptsFrom, err := keyopts.NewOptions().Set("id", r.cfg.KeyID(), "partyid", string(from))
	if err != nil {
		return errors.WithMessage(err, "sign.round3.StoreBroadcastMessage: failed to create options")
	}

	koptsTo, err := keyopts.NewOptions().Set("id", r.cfg.KeyID(), "partyid", string(to))
	if err != nil {
		return errors.WithMessage(err, "sign.round3.StoreBroadcastMessage: failed to create options")
	}

	soptsFrom, err := keyopts.NewOptions().Set("id", r.cfg.ID(), "partyid", string(from))
	if err != nil {
		return errors.WithMessage(err, "sign.round3.StoreBroadcastMessage: failed to create options")
	}

	soptsTo, err := keyopts.NewOptions().Set("id", r.cfg.ID(), "partyid", string(to))
	if err != nil {
		return errors.WithMessage(err, "sign.round3.StoreBroadcastMessage: failed to create options")
	}

	paillierFrom, err := r.paillier_km.GetKey(koptsFrom)
	if err != nil {
		return err
	}
	paillierTo, err := r.paillier_km.GetKey(koptsTo)
	if err != nil {
		return err
	}
	pedTo, err := r.pedersen_km.GetKey(koptsTo)
	if err != nil {
		return err
	}

	gammaFrom, err := r.gamma.GetKey(soptsFrom)
	if err != nil {
		return err
	}
	gammaFrom_pek, err := r.gamma_pek.Get(soptsFrom)
	if err != nil {
		return err
	}

	eckeyFrom, err := r.ec.GetKey(soptsFrom)
	if err != nil {
		return err
	}

	shareKTo_pek, err := r.signK_pek.Get(soptsTo)
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

	kopts, err := keyopts.NewOptions().Set("id", r.cfg.KeyID(), "partyid", string(r.SelfID()))
	if err != nil {
		return errors.WithMessage(err, "sign.round3.StoreBroadcastMessage: failed to create options")
	}

	soptsFrom, err := keyopts.NewOptions().Set("id", r.cfg.ID(), "partyid", string(from))
	if err != nil {
		return errors.WithMessage(err, "sign.round3.StoreBroadcastMessage: failed to create options")
	}

	// αᵢⱼ
	paillierKey, err := r.paillier_km.GetKey(kopts)
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

	if err := r.delta_mta.SetAlpha(DeltaShareAlpha, soptsFrom); err != nil {
		return err
	}
	if er := r.chi_mta.SetAlpha(ChiShareAlpha, soptsFrom); er != nil {
		return nil
	}

	if err := r.msgmgr.Import(
		r.msgmgr.NewMessage(r.cfg.ID(), int(r.Number()), string(msg.From), true),
	); err != nil {
		return err
	}

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
	if !r.CanFinalize() {
		return nil, round.ErrNotEnoughMessages
	}

	sopts, err := keyopts.NewOptions().Set("id", r.cfg.ID(), "partyid", string(r.SelfID()))
	if err != nil {
		return nil, errors.WithMessage(err, "sign.round3.StoreBroadcastMessage: failed to create options")
	}

	kopts, err := keyopts.NewOptions().Set("id", r.cfg.KeyID(), "partyid", string(r.SelfID()))
	if err != nil {
		return nil, errors.WithMessage(err, "sign.round3.StoreBroadcastMessage: failed to create options")
	}

	// Γ = ∑ⱼ Γⱼ
	Gamma := r.Group().NewPoint()
	for _, j := range r.PartyIDs() {
		soptsj, err := keyopts.NewOptions().Set("id", r.cfg.ID(), "partyid", string(j))
		if err != nil {
			return nil, errors.WithMessage(err, "sign.round3.StoreBroadcastMessage: failed to create options")
		}
		gammaj, err := r.gamma.GetKey(soptsj)
		if err != nil {
			return nil, err
		}
		Gamma = Gamma.Add(gammaj.PublicKeyRaw())
	}
	soptsRoot, err := keyopts.NewOptions().Set("id", r.cfg.ID(), "partyid", "ROOT")
	if err != nil {
		return nil, errors.WithMessage(err, "sign.round3.StoreBroadcastMessage: failed to create options")
	}
	gammaRoot := ecdsa.NewKey(nil, Gamma, Gamma.Curve())
	if _, err := r.gamma.ImportKey(gammaRoot, soptsRoot); err != nil {
		return nil, err
	}

	// Δᵢ = [kᵢ]Γ
	KShare, err := r.signK.GetKey(sopts)
	if err != nil {
		return nil, err
	}
	bigDeltaShare := KShare.Act(Gamma, false)
	bigDelta := ecdsa.NewKey(nil, bigDeltaShare, bigDeltaShare.Curve())
	if _, err := r.bigDelta.ImportKey(bigDelta, sopts); err != nil {
		return nil, err
	}

	// δᵢ = γᵢ kᵢ + ∑ⱼ δᵢⱼ
	deltaSum := new(saferith.Int)
	for _, j := range r.OtherPartyIDs() {
		soptsj, err := keyopts.NewOptions().Set("id", r.cfg.ID(), "partyid", string(j))
		if err != nil {
			return nil, errors.WithMessage(err, "sign.round3.StoreBroadcastMessage: failed to create options")
		}
		//δᵢ += αᵢⱼ + βᵢⱼ
		deltaj, err := r.delta_mta.Get(soptsj)
		if err != nil {
			return nil, err
		}
		deltaSum = deltaSum.Add(deltaSum, deltaj.Alpha(), -1)
		deltaSum = deltaSum.Add(deltaSum, deltaj.Beta(), -1)
	}
	deltaSumScalar := r.Group().NewScalar().SetNat(deltaSum.Mod(r.Group().Order()))
	gamma, err := r.gamma.GetKey(sopts)
	if err != nil {
		return nil, err
	}
	DeltaShareScalar := gamma.CommitByKey(KShare, deltaSumScalar)
	deltaShare := ecdsa.NewKey(DeltaShareScalar, DeltaShareScalar.ActOnBase(), DeltaShareScalar.Curve())
	if _, err := r.delta.ImportKey(deltaShare, sopts); err != nil {
		return nil, err
	}

	// χᵢ = xᵢ kᵢ + ∑ⱼ χᵢⱼ
	chiSum := new(saferith.Int)
	for _, j := range r.OtherPartyIDs() {
		soptsj, err := keyopts.NewOptions().Set("id", r.cfg.ID(), "partyid", string(j))
		if err != nil {
			return nil, errors.WithMessage(err, "sign.round3.StoreBroadcastMessage: failed to create options")
		}
		chij, err := r.chi_mta.Get(soptsj)
		if err != nil {
			return nil, err
		}
		chiSum = chiSum.Add(chiSum, chij.Alpha(), -1)
		chiSum = chiSum.Add(chiSum, chij.Beta(), -1)
	}
	chiSumScalar := r.Group().NewScalar().SetNat(chiSum.Mod(r.Group().Order()))
	eckey, err := r.ec.GetKey(sopts)
	if err != nil {
		return nil, err
	}
	ChiShareScalar := eckey.CommitByKey(KShare, chiSumScalar)
	chiShare := ecdsa.NewKey(ChiShareScalar, ChiShareScalar.ActOnBase(), ChiShareScalar.Curve())
	if _, err := r.chi.ImportKey(chiShare, sopts); err != nil {
		return nil, err
	}

	// DeltaShareScalar := r.Group().NewScalar().SetNat(DeltaShare.Mod(r.Group().Order()))
	if err := r.BroadcastMessage(out, &broadcast4{
		DeltaShare:    DeltaShareScalar,
		BigDeltaShare: bigDeltaShare,
	}); err != nil {
		return r, err
	}

	paillier, err := r.paillier_km.GetKey(kopts)
	if err != nil {
		return r, err
	}

	KSharePEK, err := r.signK_pek.Get(sopts)
	if err != nil {
		return nil, err
	}

	otherIDs := r.OtherPartyIDs()
	errs := r.Pool.Parallelize(len(otherIDs), func(i int) interface{} {
		j := otherIDs[i]

		koptsj, err := keyopts.NewOptions().Set("id", r.cfg.KeyID(), "partyid", string(j))
		if err != nil {
			return errors.WithMessage(err, "sign.round1.Finalize: failed to create options")
		}

		pedj, err := r.pedersen_km.GetKey(koptsj)
		if err != nil {
			return err
		}

		proofLog, err := r.signK.NewZKLogstarProof(
			r.HashForID(r.SelfID()),
			KSharePEK,           // PEK
			KSharePEK.Encoded(), // C
			bigDeltaShare,       // X
			Gamma,               // G
			paillier.PublicKey(),
			pedj.PublicKey(),
			sopts,
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

	// update last round processed in StateManager
	if err := r.statemgr.SetLastRound(r.ID, int(r.Number())); err != nil {
		return r, err
	}

	return &round4{
		round3: r,
	}, nil
}

func (r *round3) CanFinalize() bool {
	// Verify if all parties commitments are received
	var parties []string
	for _, p := range r.OtherPartyIDs() {
		parties = append(parties, string(p))
	}
	bcstsRcvd, err := r.bcstmgr.HasAll(r.cfg.ID(), int(r.Number()), parties)
	if err != nil {
		return false
	}
	msgssRcvd, err := r.msgmgr.HasAll(r.cfg.ID(), int(r.Number()), parties)
	if err != nil {
		return false
	}
	return bcstsRcvd && msgssRcvd
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
		// BigGammaShare: r.Group().NewPoint(),
	}
}

// Number implements round.Round.
func (round3) Number() round.Number { return 3 }

func (r *round3) Equal(other round.Round) bool {
	return true
}
