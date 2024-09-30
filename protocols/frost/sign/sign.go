package sign

import (
	"fmt"

	"github.com/mr-shifu/mpc-lib/core/math/polynomial-ed25519"
	"github.com/mr-shifu/mpc-lib/core/pool"
	"github.com/mr-shifu/mpc-lib/core/protocol"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/lib/types"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ed25519"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	vssed25519 "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss-ed25519"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/config"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/message"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/result"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/state"
	"github.com/pkg/errors"
)

const (
	// Frost Sign with Threshold.
	SIGN_CONFIG_PROTOCOL_ID = "frost/sign-threshold"
	// This protocol has 3 concrete rounds.
	protocolRounds round.Number = 3
)

type FROSTSign struct {
	signcfgmgr config.SignConfigManager
	sigmgr     result.EddsaSignatureManager
	statemgr   state.MPCStateManager
	msgmgr     message.MessageManager
	bcstmgr    message.MessageManager
	eddsa_km   ed25519.Ed25519KeyManager
	ed_vss_km  ed25519.Ed25519KeyManager
	ed_sign_km ed25519.Ed25519KeyManager
	vss_mgr    vssed25519.VssKeyManager
	sign_d     ed25519.Ed25519KeyManager
	sign_e     ed25519.Ed25519KeyManager
	hash_mgr   hash.HashManager
	pl         *pool.Pool
}

var _ protocol.Processor = (*FROSTSign)(nil)

func NewFROSTSign(
	signcfgmgr config.SignConfigManager,
	statemgr state.MPCStateManager,
	sigmgr result.EddsaSignatureManager,
	msgmgr message.MessageManager,
	bcstmgr message.MessageManager,
	eddsa_km ed25519.Ed25519KeyManager,
	ed_vss_km ed25519.Ed25519KeyManager,
	ed_sign_km ed25519.Ed25519KeyManager,
	vss_mgr vssed25519.VssKeyManager,
	sign_d ed25519.Ed25519KeyManager,
	sign_e ed25519.Ed25519KeyManager,
	hash_mgr hash.HashManager,
	pl *pool.Pool) *FROSTSign {
	return &FROSTSign{
		signcfgmgr: signcfgmgr,
		sigmgr:     sigmgr,
		statemgr:   statemgr,
		msgmgr:     msgmgr,
		bcstmgr:    bcstmgr,
		eddsa_km:   eddsa_km,
		ed_vss_km:  ed_vss_km,
		ed_sign_km: ed_sign_km,
		vss_mgr:    vss_mgr,
		sign_d:     sign_d,
		sign_e:     sign_e,
		hash_mgr:   hash_mgr,
		pl:         pl,
	}
}

func (f *FROSTSign) Start(configs any) protocol.StartFunc {
	cfg, ok := configs.(config.SignConfig)
	if !ok {
		return nil
	}

	return func(sessionID []byte) (round.Session, error) {
		info := round.Info{
			ProtocolID:       SIGN_CONFIG_PROTOCOL_ID,
			FinalRoundNumber: protocolRounds,
			SelfID:           cfg.SelfID(),
			PartyIDs:         cfg.PartyIDs(),
		}

		opts, err := keyopts.NewOptions().Set("id", cfg.ID(), "partyid", info.SelfID)
		if err != nil {
			return nil, errors.New("frost_sign: failed to set options")
		}

		h := f.hash_mgr.NewHasher(cfg.ID(), opts)

		// validate message is not empty
		if len(cfg.Message()) == 0 {
			return nil, errors.New("sign.Create: message is nil")
		}

		// create a new helper
		helper, err := round.NewSession(cfg.ID(), info, sessionID, f.pl, h, types.SigningMessage(cfg.Message()))
		if err != nil {
			return nil, fmt.Errorf("sign.StartSign: %w", err)
		}

		// clone the vss share multiplied by the lagrange coefficient
		lagrange, err := polynomial.Lagrange(cfg.PartyIDs())
		if err != nil {
			return nil, err
		}
		for _, j := range helper.PartyIDs() {
			partyVSSOpts, err := keyopts.NewOptions().Set("id", cfg.KeyID(), "partyid", string(j))
			if err != nil {
				return nil, errors.New("frost_sign: failed to set options")
			}

			vssShareKey, err := f.ed_vss_km.GetKey(partyVSSOpts)
			if err != nil {
				return nil, err
			}

			partyOpts, err := keyopts.NewOptions().Set("id", cfg.ID(), "partyid", string(j))
			if err != nil {
				return nil, errors.New("frost_sign: failed to set options")
			}
			clonedj := vssShareKey.Multiply(lagrange[j])
			if err != nil {
				return nil, err
			}
			if _, err := f.ed_sign_km.ImportKey(clonedj, partyOpts); err != nil {
				return nil, err
			}
		}

		if err := f.signcfgmgr.ImportConfig(cfg); err != nil {
			return nil, err
		}

		if err := f.statemgr.NewState(cfg.ID()); err != nil {
			return nil, err
		}

		return &round1{
			Helper:     helper,
			cfg:        cfg,
			statemgr:   f.statemgr,
			sigmgr:     f.sigmgr,
			msgmgr:     f.msgmgr,
			bcstmgr:    f.bcstmgr,
			eddsa_km:   f.eddsa_km,
			ed_vss_km:  f.ed_vss_km,
			ed_sign_km: f.ed_sign_km,
			vss_mgr:    f.vss_mgr,
			sign_d:     f.sign_d,
			sign_e:     f.sign_e,
			hash_mgr:   f.hash_mgr,
		}, nil
	}
}

func (f *FROSTSign) GetRound(signID string) (round.Session, error) {
	cfg, err := f.signcfgmgr.GetConfig(signID)
	if err != nil {
		return nil, errors.WithMessage(err, "frost_sign: failed to get config")
	}

	info := round.Info{
		ProtocolID:       SIGN_CONFIG_PROTOCOL_ID,
		SelfID:           cfg.SelfID(),
		PartyIDs:         cfg.PartyIDs(),
		FinalRoundNumber: protocolRounds,
	}
	// instantiate a new hasher for new sign session
	opts, err := keyopts.NewOptions().Set("id", cfg.ID(), "partyid", string(info.SelfID))
	if err != nil {
		return nil, errors.New("frost_sign: failed to set options")
	}
	h := f.hash_mgr.NewHasher(cfg.ID(), opts)

	// generate new helper for new sign session
	helper, err := round.NewSession(cfg.ID(), info, nil, f.pl, h)
	if err != nil {
		return nil, fmt.Errorf("frost_sign: %w", err)
	}

	state, err := f.statemgr.Get(signID)
	if err != nil {
		return nil, errors.WithMessage(err, "frost_sign: failed to get state")
	}
	rn := state.LastRound()
	switch rn {
	case 0:
		return &round1{
			Helper:     helper,
			cfg:        cfg,
			statemgr:   f.statemgr,
			sigmgr:     f.sigmgr,
			msgmgr:     f.msgmgr,
			bcstmgr:    f.bcstmgr,
			eddsa_km:   f.eddsa_km,
			ed_vss_km:  f.ed_vss_km,
			ed_sign_km: f.ed_sign_km,
			vss_mgr:    f.vss_mgr,
			sign_d:     f.sign_d,
			sign_e:     f.sign_e,
			hash_mgr:   f.hash_mgr,
		}, nil
	case 1:
		return &round2{
			Helper:     helper,
			cfg:        cfg,
			statemgr:   f.statemgr,
			sigmgr:     f.sigmgr,
			msgmgr:     f.msgmgr,
			bcstmgr:    f.bcstmgr,
			eddsa_km:   f.eddsa_km,
			ed_vss_km:  f.ed_vss_km,
			ed_sign_km: f.ed_sign_km,
			vss_mgr:    f.vss_mgr,
			sign_d:     f.sign_d,
			sign_e:     f.sign_e,
			hash_mgr:   f.hash_mgr,
		}, nil
	case 2:
		return &round3{
			Helper:     helper,
			cfg:        cfg,
			statemgr:   f.statemgr,
			sigmgr:     f.sigmgr,
			msgmgr:     f.msgmgr,
			bcstmgr:    f.bcstmgr,
			eddsa_km:   f.eddsa_km,
			ed_vss_km:  f.ed_vss_km,
			ed_sign_km: f.ed_sign_km,
			vss_mgr:    f.vss_mgr,
			sign_d:     f.sign_d,
			sign_e:     f.sign_e,
			hash_mgr:   f.hash_mgr,
		}, nil
	default:
		return nil, errors.New("frost_sign: invalid round number")
	}
}

func (f *FROSTSign) StoreBroadcastMessage(signID string, msg round.Message) error {
	r, err := f.GetRound(signID)
	if err != nil {
		return errors.WithMessage(err, "frost_sign: failed to get round")
	}

	if err := r.StoreBroadcastMessage(msg); err != nil {
		return errors.WithMessage(err, "frost_sign: failed to store message")
	}

	return nil
}

func (f *FROSTSign) StoreMessage(signID string, msg round.Message) error {
	r, err := f.GetRound(signID)
	if err != nil {
		return errors.WithMessage(err, "frost_sign: failed to get round")
	}

	if err := r.StoreMessage(msg); err != nil {
		return errors.WithMessage(err, "frost_sign: failed to store message")
	}

	return nil
}

func (f *FROSTSign) Finalize(out chan<- *round.Message, signID string) (round.Session, error) {
	r, err := f.GetRound(signID)
	if err != nil {
		return nil, errors.WithMessage(err, "frost_sign: failed to get round")
	}

	return r.Finalize(out)
}

func (m *FROSTSign) CanFinalize(signID string) (bool, error) {
	r, err := m.GetRound(signID)
	if err != nil {
		return false, errors.WithMessage(err, "frost_sign: failed to get round")
	}
	return r.CanFinalize(), nil
}

func (m *FROSTSign) CanStoreMessage(signID string, roundNumber int) (bool, error) {
	state, err := m.statemgr.Get(signID)
	if err != nil {
		return false, errors.WithMessage(err, "cmp.Sign: failed to get state")
	}
	rn := state.LastRound()
	if rn != roundNumber-1 {
		return false, nil
	}
	return true, nil
}
