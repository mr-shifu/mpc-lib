package sign

import (
	"encoding/hex"
	"fmt"

	"github.com/mr-shifu/mpc-lib/core/math/polynomial"
	"github.com/mr-shifu/mpc-lib/core/pool"
	"github.com/mr-shifu/mpc-lib/core/protocol"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/lib/types"
	"github.com/pkg/errors"

	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/mta"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillier"
	pek "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillierencodedkey"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/pedersen"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/config"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/message"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/result"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/state"
)

// protocolSignID for the "3 round" variant using echo broadcast.
const (
	protocolSignID                  = "cmp/sign"
	protocolSignRounds round.Number = 5
)

type MPCSign struct {
	signcfgmgr config.SignConfigManager
	statmgr    state.MPCStateManager
	msgmgr     message.MessageManager
	bcstmgr    message.MessageManager

	hash_mgr hash.HashManager

	paillier_km paillier.PaillierKeyManager

	pedersen_km pedersen.PedersenKeyManager

	ec       ecdsa.ECDSAKeyManager
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

	sigmgr result.EcdsaSignatureManager

	pl *pool.Pool
}

func NewMPCSign(
	signcfgmgr config.SignConfigManager,
	statmanager state.MPCStateManager,
	msgmgr message.MessageManager,
	bcstmgr message.MessageManager,
	hash_mgr hash.HashManager,
	paillier_km paillier.PaillierKeyManager,
	pedersen_km pedersen.PedersenKeyManager,
	ec ecdsa.ECDSAKeyManager,
	ec_vss ecdsa.ECDSAKeyManager,
	vss_mgr vss.VssKeyManager,
	gamma ecdsa.ECDSAKeyManager,
	signK ecdsa.ECDSAKeyManager,
	delta ecdsa.ECDSAKeyManager,
	chi ecdsa.ECDSAKeyManager,
	bigDelta ecdsa.ECDSAKeyManager,
	gamma_pek pek.PaillierEncodedKeyManager,
	signK_pek pek.PaillierEncodedKeyManager,
	delta_mta mta.MtAManager,
	chi_mta mta.MtAManager,
	sigmgr result.EcdsaSignatureManager,
	pl *pool.Pool,
) *MPCSign {
	return &MPCSign{
		signcfgmgr:  signcfgmgr,
		statmgr:     statmanager,
		msgmgr:      msgmgr,
		bcstmgr:     bcstmgr,
		hash_mgr:    hash_mgr,
		paillier_km: paillier_km,
		pedersen_km: pedersen_km,
		ec:          ec,
		ec_vss:      ec_vss,
		vss_mgr:     vss_mgr,
		gamma:       gamma,
		signK:       signK,
		delta:       delta,
		chi:         chi,
		bigDelta:    bigDelta,
		gamma_pek:   gamma_pek,
		signK_pek:   signK_pek,
		delta_mta:   delta_mta,
		chi_mta:     chi_mta,
		sigmgr:      sigmgr,
		pl:          pl,
	}
}

func (m *MPCSign) Start(cfg any) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		cfg, ok := cfg.(config.SignConfig)
		if !ok {
			return nil, errors.New("sign.Create: invalid config")
		}

		info := round.Info{
			ProtocolID:       "cmp/sign",
			FinalRoundNumber: 5,
			SelfID:           cfg.SelfID(),
			PartyIDs:         cfg.PartyIDs(),
			Threshold:        cfg.Threshold(),
			Group:            cfg.Group(),
		}
		group := info.Group

		opts, err := keyopts.NewOptions().Set("id", cfg.ID(), "partyid", info.SelfID)
		if err != nil {
			return nil, errors.WithMessage(err, "sign.Create: failed to create options")
		}

		h := m.hash_mgr.NewHasher(cfg.ID(), opts)

		// this could be used to indicate a pre-signature later on
		if len(cfg.Message()) == 0 {
			return nil, errors.New("sign.Create: message is nil")
		}

		helper, err := round.NewSession(cfg.ID(), info, sessionID, m.pl, h, types.SigningMessage(cfg.Message()))
		if err != nil {
			return nil, fmt.Errorf("sign.Create: %w", err)
		}

		// if !config.CanSign(helper.PartyIDs()) {
		// 	return nil, errors.New("sign.Create: signers is not a valid signing subset")
		// }

		// Scale public data

		lagrange := polynomial.Lagrange(group, cfg.PartyIDs())
		clonedPubKey := info.Group.NewPoint()
		for _, j := range helper.PartyIDs() {
			vssOpts, err := keyopts.NewOptions().Set("id", cfg.KeyID(), "partyid", "ROOT")
			if err != nil {
				return nil, errors.WithMessage(err, "sign.Create: failed to create options")
			}
			vss, err := m.vss_mgr.GetSecrets(vssOpts)
			if err != nil {
				return nil, err
			}

			partyVSSOpts, err := keyopts.NewOptions().Set("id", hex.EncodeToString(vss.SKI()), "partyid", string(j))
			if err != nil {
				return nil, errors.WithMessage(err, "sign.Create: failed to create options")
			}

			partyOpts, err := keyopts.NewOptions().Set("id", cfg.ID(), "partyid", string(j))
			if err != nil {
				return nil, errors.WithMessage(err, "sign.Create: failed to create options")
			}
			clonedj, err := m.ec_vss.CloneByMultiplier(lagrange[j], partyVSSOpts)
			if err != nil {
				return nil, err
			}
			if _, err := m.ec.ImportKey(clonedj, partyOpts); err != nil {
				return nil, err
			}
			clonedPubKey = clonedPubKey.Add(clonedj.PublicKeyRaw())
		}
		rootECOpts, err := keyopts.NewOptions().Set("id", cfg.ID(), "partyid", "ROOT")
		if err != nil {
			return nil, errors.WithMessage(err, "sign.Create: failed to create options")
		}
		cloned := ecdsa.NewKey(nil, clonedPubKey, info.Group)
		if _, err := m.ec.ImportKey(cloned, rootECOpts); err != nil {
			return nil, err
		}

		if err := m.signcfgmgr.ImportConfig(cfg); err != nil {
			return nil, fmt.Errorf("keygen: %w", err)
		}

		if err := m.statmgr.NewState(cfg.ID()); err != nil {
			return nil, err
		}

		return &round1{
			Helper:      helper,
			cfg:         cfg,
			statemgr:    m.statmgr,
			msgmgr:      m.msgmgr,
			bcstmgr:     m.bcstmgr,
			hash_mgr:    m.hash_mgr,
			paillier_km: m.paillier_km,
			pedersen_km: m.pedersen_km,
			ec:          m.ec,
			vss_mgr:     m.vss_mgr,
			gamma:       m.gamma,
			signK:       m.signK,
			delta:       m.delta,
			chi:         m.chi,
			bigDelta:    m.bigDelta,
			gamma_pek:   m.gamma_pek,
			signK_pek:   m.signK_pek,
			delta_mta:   m.delta_mta,
			chi_mta:     m.chi_mta,
			sigmgr:      m.sigmgr,
		}, nil
	}
}

func (m *MPCSign) GetRound(signID string) (round.Session, error) {
	cfg, err := m.signcfgmgr.GetConfig(signID)
	if err != nil {
		return nil, errors.WithMessage(err, "cmp_sign: failed to get config")
	}

	info := round.Info{
		ProtocolID:       "cmp/sign",
		SelfID:           cfg.SelfID(),
		PartyIDs:         cfg.PartyIDs(),
		Threshold:        cfg.Threshold(),
		Group:            cfg.Group(),
		FinalRoundNumber: 5,
	}

	// generate new helper for new sign session
	helper, err := round.ResumeSession(cfg.KeyID(), info, nil, m.pl, m.hash_mgr)
	if err != nil {
		return nil, fmt.Errorf("cmp_sign: %w", err)
	}

	state, err := m.statmgr.Get(signID)
	if err != nil {
		return nil, errors.WithMessage(err, "cmp_sign: failed to get state")
	}
	rn := state.LastRound()
	switch rn {
	case 0:
		return &round1{
			Helper:      helper,
			cfg:         cfg,
			statemgr:    m.statmgr,
			msgmgr:      m.msgmgr,
			bcstmgr:     m.bcstmgr,
			hash_mgr:    m.hash_mgr,
			paillier_km: m.paillier_km,
			pedersen_km: m.pedersen_km,
			ec:          m.ec,
			vss_mgr:     m.vss_mgr,
			gamma:       m.gamma,
			signK:       m.signK,
			delta:       m.delta,
			chi:         m.chi,
			bigDelta:    m.bigDelta,
			gamma_pek:   m.gamma_pek,
			signK_pek:   m.signK_pek,
			delta_mta:   m.delta_mta,
			chi_mta:     m.chi_mta,
			sigmgr:      m.sigmgr,
		}, nil
	case 1:
		return &round2{
			Helper:      helper,
			cfg:         cfg,
			statemgr:    m.statmgr,
			msgmgr:      m.msgmgr,
			bcstmgr:     m.bcstmgr,
			hash_mgr:    m.hash_mgr,
			paillier_km: m.paillier_km,
			pedersen_km: m.pedersen_km,
			ec:          m.ec,
			vss_mgr:     m.vss_mgr,
			gamma:       m.gamma,
			signK:       m.signK,
			delta:       m.delta,
			chi:         m.chi,
			bigDelta:    m.bigDelta,
			gamma_pek:   m.gamma_pek,
			signK_pek:   m.signK_pek,
			delta_mta:   m.delta_mta,
			chi_mta:     m.chi_mta,
			sigmgr:      m.sigmgr,
		}, nil
	case 2:
		return &round3{
			Helper:      helper,
			cfg:         cfg,
			statemgr:    m.statmgr,
			msgmgr:      m.msgmgr,
			bcstmgr:     m.bcstmgr,
			hash_mgr:    m.hash_mgr,
			paillier_km: m.paillier_km,
			pedersen_km: m.pedersen_km,
			ec:          m.ec,
			vss_mgr:     m.vss_mgr,
			gamma:       m.gamma,
			signK:       m.signK,
			delta:       m.delta,
			chi:         m.chi,
			bigDelta:    m.bigDelta,
			gamma_pek:   m.gamma_pek,
			signK_pek:   m.signK_pek,
			delta_mta:   m.delta_mta,
			chi_mta:     m.chi_mta,
			sigmgr:      m.sigmgr,
		}, nil
	case 3:
		return &round4{
			Helper:      helper,
			cfg:         cfg,
			statemgr:    m.statmgr,
			msgmgr:      m.msgmgr,
			bcstmgr:     m.bcstmgr,
			hash_mgr:    m.hash_mgr,
			paillier_km: m.paillier_km,
			pedersen_km: m.pedersen_km,
			ec:          m.ec,
			vss_mgr:     m.vss_mgr,
			gamma:       m.gamma,
			signK:       m.signK,
			delta:       m.delta,
			chi:         m.chi,
			bigDelta:    m.bigDelta,
			gamma_pek:   m.gamma_pek,
			signK_pek:   m.signK_pek,
			delta_mta:   m.delta_mta,
			chi_mta:     m.chi_mta,
			sigmgr:      m.sigmgr,
		}, nil
	case 4:
		return &round5{
			Helper:      helper,
			cfg:         cfg,
			statemgr:    m.statmgr,
			msgmgr:      m.msgmgr,
			bcstmgr:     m.bcstmgr,
			hash_mgr:    m.hash_mgr,
			paillier_km: m.paillier_km,
			pedersen_km: m.pedersen_km,
			ec:          m.ec,
			vss_mgr:     m.vss_mgr,
			gamma:       m.gamma,
			signK:       m.signK,
			delta:       m.delta,
			chi:         m.chi,
			bigDelta:    m.bigDelta,
			gamma_pek:   m.gamma_pek,
			signK_pek:   m.signK_pek,
			delta_mta:   m.delta_mta,
			chi_mta:     m.chi_mta,
			sigmgr:      m.sigmgr,
		}, nil
	default:
		return nil, errors.New("cmp_sign: invalid round number")
	}
}

func (m *MPCSign) StoreBroadcastMessage(signID string, msg round.Message) error {
	r, err := m.GetRound(signID)
	if err != nil {
		return errors.WithMessage(err, "cmp_sign: failed to get round")
	}

	if err := r.StoreBroadcastMessage(msg); err != nil {
		return errors.WithMessage(err, "cmp_sign: failed to store message")
	}

	return nil
}

func (f *MPCSign) StoreMessage(signID string, msg round.Message) error {
	r, err := f.GetRound(signID)
	if err != nil {
		return errors.WithMessage(err, "cmp_sign: failed to get round")
	}

	if err := r.StoreMessage(msg); err != nil {
		return errors.WithMessage(err, "cmp_sign: failed to store message")
	}

	return nil
}

func (f *MPCSign) Finalize(out chan<- *round.Message, signID string) (round.Session, error) {
	r, err := f.GetRound(signID)
	if err != nil {
		return nil, errors.WithMessage(err, "cmp_sign: failed to get round")
	}

	return r.Finalize(out)
}

func (m *MPCSign) CanFinalize(signID string) (bool, error) {
	r, err := m.GetRound(signID)
	if err != nil {
		return false, errors.WithMessage(err, "cmp_sign: failed to get round")
	}
	return r.CanFinalize(), nil
}
