package sign

import (
	"github.com/cronokirby/saferith"
	core_paillier "github.com/mr-shifu/mpc-lib/core/paillier"
	zkenc "github.com/mr-shifu/mpc-lib/core/zk/enc"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/mta"
	sw_mta "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/mta"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillier"
	pek "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillierencodedkey"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/pedersen"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/config"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/message"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/result"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/state"
	"github.com/pkg/errors"
)

var _ round.Round = (*round2)(nil)

type round2 struct {
	*round.Helper

	cfg      config.SignConfig
	statemgr state.MPCStateManager
	sigmgr   result.EcdsaSignatureManager
	msgmgr   message.MessageManager
	bcstmgr  message.MessageManager

	hash_mgr    hash.HashManager
	paillier_km paillier.PaillierKeyManager
	pedersen_km pedersen.PedersenKeyManager

	ec_key   ecdsa.ECDSAKeyManager
	ec_sig   ecdsa.ECDSAKeyManager
	ec_vss   ecdsa.ECDSAKeyManager
	gamma    ecdsa.ECDSAKeyManager
	signK    ecdsa.ECDSAKeyManager
	delta    ecdsa.ECDSAKeyManager
	chi      ecdsa.ECDSAKeyManager
	bigDelta ecdsa.ECDSAKeyManager

	vss_mgr vss.VssKeyManager

	gamma_pek pek.PaillierEncodedKeyManager
	signK_pek pek.PaillierEncodedKeyManager

	delta_mta mta.MtAManager
	chi_mta   mta.MtAManager
}

type broadcast2 struct {
	round.ReliableBroadcastContent
	// K = Kᵢ
	K *core_paillier.Ciphertext
	// G = Gᵢ
	G *core_paillier.Ciphertext
}

type message2 struct {
	ProofEnc *zkenc.Proof
}

// StoreBroadcastMessage implements round.Round.
//
// - store Kⱼ, Gⱼ.
func (r *round2) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcast2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	koptsFrom, err := keyopts.NewOptions().Set("id", r.cfg.KeyID(), "partyid", string(from))
	if err != nil {
		return errors.WithMessage(err, "sign.round2.StoreBroadcastMessage: failed to create options")
	}

	soptsFrom, err := keyopts.NewOptions().Set("id", r.cfg.ID(), "partyid", string(from))
	if err != nil {
		return errors.WithMessage(err, "sign.round2.StoreBroadcastMessage: failed to create options")
	}

	paillierj, err := r.paillier_km.GetKey(koptsFrom)
	if err != nil {
		return err
	}

	if !paillierj.ValidateCiphertexts(body.K, body.G) {
		return errors.New("invalid K, G")
	}

	k_pekj := pek.NewPaillierEncodedKeyImpl(nil, body.K, nil, r.Group())
	if _, err := r.signK_pek.Import(k_pekj, soptsFrom); err != nil {
		return err
	}

	gamma_pekj := pek.NewPaillierEncodedKeyImpl(nil, body.G, nil, r.Group())
	if _, err := r.gamma_pek.Import(gamma_pekj, soptsFrom); err != nil {
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
// - verify zkenc(Kⱼ).
func (r *round2) VerifyMessage(msg round.Message) error {
	from, to := msg.From, msg.To
	body, ok := msg.Content.(*message2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if body.ProofEnc == nil {
		return round.ErrNilFields
	}

	koptsFrom, err := keyopts.NewOptions().Set("id", r.cfg.KeyID(), "partyid", string(from))
	if err != nil {
		return errors.WithMessage(err, "sign.round2.StoreBroadcastMessage: failed to create options")
	}

	koptsTo, err := keyopts.NewOptions().Set("id", r.cfg.KeyID(), "partyid", string(to))
	if err != nil {
		return errors.WithMessage(err, "sign.round2.StoreBroadcastMessage: failed to create options")
	}

	soptsFrom, err := keyopts.NewOptions().Set("id", r.cfg.ID(), "partyid", string(from))
	if err != nil {
		return errors.WithMessage(err, "sign.round2.StoreBroadcastMessage: failed to create options")
	}

	paillierFrom, err := r.paillier_km.GetKey(koptsFrom)
	if err != nil {
		return err
	}
	pedersenTo, err := r.pedersen_km.GetKey(koptsTo)
	if err != nil {
		return err
	}

	Kj, err := r.signK_pek.Get(soptsFrom)
	if err != nil {
		return err
	}
	if !body.ProofEnc.Verify(r.Group(), r.HashForID(from), zkenc.Public{
		K:      Kj.Encoded(),
		Prover: paillierFrom.PublicKeyRaw(),
		Aux:    pedersenTo.PublicKeyRaw(),
	}) {
		return errors.New("failed to validate enc proof for K")
	}
	return nil
}

// StoreMessage implements round.Round.
//
// - store Kⱼ, Gⱼ.
func (round2) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
//
// - compute Hash(ssid, K₁, G₁, …, Kₙ, Gₙ).
func (r *round2) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Verify if all parties commitments are received
	if !r.CanFinalize() {
		return nil, round.ErrNotEnoughMessages
	}

	sopts, err := keyopts.NewOptions().Set("id", r.cfg.ID(), "partyid", string(r.SelfID()))
	if err != nil {
		return nil, errors.WithMessage(err, "sign.round2.StoreBroadcastMessage: failed to create options")
	}

	kopts, err := keyopts.NewOptions().Set("id", r.cfg.KeyID(), "partyid", string(r.SelfID()))
	if err != nil {
		return nil, errors.WithMessage(err, "sign.round2.StoreBroadcastMessage: failed to create options")
	}

	// Retreive Gamma key from keystore
	gamma, err := r.gamma.GetKey(sopts)
	if err != nil {
		return r, err
	}

	gamma_bytes, err := gamma.Bytes()
	if err != nil {
		return r, err
	}

	if err := r.BroadcastMessage(out, &broadcast3{
		BigGammaShare: gamma_bytes,
	}); err != nil {
		return r, err
	}

	otherIDs := r.OtherPartyIDs()
	type mtaOut struct {
		err       error
		DeltaBeta *saferith.Int
		ChiBeta   *saferith.Int
	}
	mtaOuts := r.Pool.Parallelize(len(otherIDs), func(i int) interface{} {
		j := otherIDs[i]

		soptsj, err := keyopts.NewOptions().Set("id", r.cfg.ID(), "partyid", string(j))
		if err != nil {
			return errors.WithMessage(err, "sign.round2.StoreBroadcastMessage: failed to create options")
		}

		koptsj, err := keyopts.NewOptions().Set("id", r.cfg.KeyID(), "partyid", string(j))
		if err != nil {
			return errors.WithMessage(err, "sign.round2.StoreBroadcastMessage: failed to create options")
		}

		// TODO must be changed to signID
		gamma, err := r.gamma.GetKey(sopts)
		if err != nil {
			return err
		}
		paillierKey, err := r.paillier_km.GetKey(kopts)
		if err != nil {
			return err
		}
		paillierj, err := r.paillier_km.GetKey(koptsj)
		if err != nil {
			return err
		}
		pedj, err := r.pedersen_km.GetKey(koptsj)
		if err != nil {
			return err
		}
		k_pek, err := r.signK_pek.Get(soptsj)
		if err != nil {
			return err
		}

		DeltaBeta, DeltaD, DeltaF, DeltaProof, err := r.gamma.NewMtAAffgProof(
			r.HashForID(r.SelfID()),
			k_pek.Encoded(),
			paillierKey.PublicKey(),
			paillierj.PublicKey(),
			pedj.PublicKey(),
			sopts,
		)
		if err != nil {
			return err
		}

		ChiBeta, ChiD, ChiF, ChiProof, err := r.ec_sig.NewMtAAffgProof(
			r.HashForID(r.SelfID()),
			k_pek.Encoded(),
			paillierKey.PublicKey(),
			paillierj.PublicKey(),
			pedj.PublicKey(),
			sopts,
		)
		if err != nil {
			return err
		}

		gammaPEK, err := r.gamma_pek.Get(sopts)
		if err != nil {
			return err
		}
		proof, err := r.gamma.NewZKLogstarProof(
			r.HashForID(r.SelfID()),
			gammaPEK,
			gammaPEK.Encoded(),
			gamma.PublicKeyRaw(),
			nil,
			paillierKey.PublicKey(),
			pedj.PublicKey(),
			sopts,
		)
		if err != nil {
			return err
		}

		err = r.SendMessage(out, &message3{
			DeltaD:     DeltaD,
			DeltaF:     DeltaF,
			DeltaProof: DeltaProof,
			ChiD:       ChiD,
			ChiF:       ChiF,
			ChiProof:   ChiProof,
			ProofLog:   proof,
		}, j)
		return mtaOut{
			err:       err,
			DeltaBeta: DeltaBeta,
			ChiBeta:   ChiBeta,
		}
	})

	for idx, mtaOutRaw := range mtaOuts {
		j := otherIDs[idx]
		m := mtaOutRaw.(mtaOut)
		if m.err != nil {
			return r, m.err
		}

		soptsj, err := keyopts.NewOptions().Set("id", r.cfg.ID(), "partyid", string(j))
		if err != nil {
			return nil, errors.WithMessage(err, "sign.round2.StoreBroadcastMessage: failed to create options")
		}

		delta_mta := sw_mta.NewMtA(nil, m.DeltaBeta)
		if err := r.delta_mta.Import(delta_mta, soptsj); err != nil {
			return nil, err
		}
		chi_mta := sw_mta.NewMtA(nil, m.ChiBeta)
		if err := r.chi_mta.Import(chi_mta, soptsj); err != nil {
			return nil, err
		}
	}

	// update last round processed in StateManager
	if err := r.statemgr.SetLastRound(r.cfg.ID(), int(r.Number())); err != nil {
		return r, err
	}

	return &round3{
		Helper:      r.Helper,
		cfg:         r.cfg,
		statemgr:    r.statemgr,
		msgmgr:      r.msgmgr,
		bcstmgr:     r.bcstmgr,
		hash_mgr:    r.hash_mgr,
		paillier_km: r.paillier_km,
		pedersen_km: r.pedersen_km,
		ec_key:      r.ec_key,
		ec_sig:      r.ec_sig,
		vss_mgr:     r.vss_mgr,
		gamma:       r.gamma,
		signK:       r.signK,
		delta:       r.delta,
		chi:         r.chi,
		bigDelta:    r.bigDelta,
		gamma_pek:   r.gamma_pek,
		signK_pek:   r.signK_pek,
		delta_mta:   r.delta_mta,
		chi_mta:     r.chi_mta,
		sigmgr:      r.sigmgr,
	}, nil
}

func (r *round2) CanFinalize() bool {
	// Verify if all parties commitments are received
	var parties []string
	for _, p := range r.OtherPartyIDs() {
		parties = append(parties, string(p))
	}
	rcvd, err := r.bcstmgr.HasAll(r.cfg.ID(), int(r.Number()), parties)
	if err != nil {
		return false
	}
	return rcvd
}

// RoundNumber implements round.Content.
func (message2) RoundNumber() round.Number { return 2 }

// MessageContent implements round.Round.
func (round2) MessageContent() round.Content { return &message2{} }

// RoundNumber implements round.Content.
func (broadcast2) RoundNumber() round.Number { return 2 }

// BroadcastContent implements round.BroadcastRound.
func (round2) BroadcastContent() round.BroadcastContent { return &broadcast2{} }

// Number implements round.Round.
func (round2) Number() round.Number { return 2 }

func (r *round2) Equal(other round.Round) bool {
	return true
}
