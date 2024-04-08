package sign

import (
	"errors"
	"fmt"

	"github.com/cronokirby/saferith"
	"github.com/mr-shifu/mpc-lib/core/paillier"
	"github.com/mr-shifu/mpc-lib/core/party"
	zkaffg "github.com/mr-shifu/mpc-lib/core/zk/affg"
	zklogstar "github.com/mr-shifu/mpc-lib/core/zk/logstar"
	"github.com/mr-shifu/mpc-lib/lib/round"
	sw_ecdsa "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
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

	soptsFrom := keyopts.Options{}
	soptsFrom.Set("id", r.cfg.ID(), "partyid", string(msg.From))

	// gamma := sw_ecdsa.NewECDSAKey(nil, body.BigGammaShare, body.BigGammaShare.Curve())
	if _, err := r.gamma.ImportKey(body.BigGammaShare, soptsFrom); err != nil {
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

	koptsFrom := keyopts.Options{}
	koptsFrom.Set("id", r.cfg.KeyID(), "partyid", string(from))

	koptsTo := keyopts.Options{}
	koptsTo.Set("id", r.cfg.KeyID(), "partyid", string(to))

	soptsFrom := keyopts.Options{}
	soptsFrom.Set("id", r.cfg.ID(), "partyid", string(from))

	soptsTo := keyopts.Options{}
	soptsTo.Set("id", r.cfg.ID(), "partyid", string(to))

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

	kopts := keyopts.Options{}
	kopts.Set("id", r.cfg.KeyID(), "partyid", string(r.SelfID()))

	soptsFrom := keyopts.Options{}
	soptsFrom.Set("id", r.cfg.ID(), "partyid", string(from))

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

	sopts := keyopts.Options{}
	sopts.Set("id", r.cfg.ID(), "partyid", string(r.SelfID()))

	kopts := keyopts.Options{}
	kopts.Set("id", r.cfg.KeyID(), "partyid", string(r.SelfID()))

	// Γ = ∑ⱼ Γⱼ
	Gamma := r.Group().NewPoint()
	for _, j := range r.PartyIDs() {
		soptsj := keyopts.Options{}
		soptsj.Set("id", r.cfg.ID(), "partyid", string(j))
		gammaj, err := r.gamma.GetKey(soptsj)
		if err != nil {
			return nil, err
		}
		Gamma = Gamma.Add(gammaj.PublicKeyRaw())
	}
	soptsRoot := keyopts.Options{}
	soptsRoot.Set("id", r.cfg.ID(), "partyid", "ROOT")
	gammaRoot := sw_ecdsa.NewECDSAKey(nil, Gamma, Gamma.Curve())
	if _, err := r.gamma.ImportKey(gammaRoot, soptsRoot); err != nil {
		return nil, err
	}

	// Δᵢ = [kᵢ]Γ
	KShare, err := r.signK.GetKey(sopts)
	if err != nil {
		return nil, err
	}
	bigDeltaShare := KShare.Act(Gamma, false)
	bigDelta := sw_ecdsa.NewECDSAKey(nil, bigDeltaShare, bigDeltaShare.Curve())
	if _, err := r.bigDelta.ImportKey(bigDelta, sopts); err != nil {
		return nil, err
	}

	// δᵢ = γᵢ kᵢ + ∑ⱼ δᵢⱼ
	deltaSum := new(saferith.Int)
	for _, j := range r.OtherPartyIDs() {
		soptsj := keyopts.Options{}
		soptsj.Set("id", r.cfg.ID(), "partyid", string(j))
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
	deltaShare := sw_ecdsa.NewECDSAKey(DeltaShareScalar, DeltaShareScalar.ActOnBase(), DeltaShareScalar.Curve())
	if _, err := r.delta.ImportKey(deltaShare, sopts); err != nil {
		return nil, err
	}

	// χᵢ = xᵢ kᵢ + ∑ⱼ χᵢⱼ
	chiSum := new(saferith.Int)
	for _, j := range r.OtherPartyIDs() {
		soptsj := keyopts.Options{}
		soptsj.Set("id", r.cfg.ID(), "partyid", string(j))
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
	chiShare := sw_ecdsa.NewECDSAKey(ChiShareScalar, ChiShareScalar.ActOnBase(), ChiShareScalar.Curve())
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

		koptsj := keyopts.Options{}
		koptsj.Set("id", r.cfg.KeyID(), "partyid", string(j))

		pedj, err := r.pedersen_km.GetKey(koptsj)
		if err != nil {
			return err
		}

		proofLog, err := KShare.NewZKLogstarProof(
			r.HashForID(r.SelfID()),
			KSharePEK,           // PEK
			KSharePEK.Encoded(), // C
			bigDeltaShare,       // X
			Gamma,               // G
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
		// BigGammaShare: r.Group().NewPoint(),
	}
}

// Number implements round.Round.
func (round3) Number() round.Number { return 3 }

func (r *round3) Equal(other round.Round) bool {
	return true
}
