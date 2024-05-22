package sign

import (
	"encoding/hex"
	"fmt"

	"github.com/mr-shifu/mpc-lib/core/math/polynomial"
	"github.com/mr-shifu/mpc-lib/core/pool"
	"github.com/mr-shifu/mpc-lib/core/protocol"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/lib/types"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/vss"
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
	ecdsa_km   ecdsa.ECDSAKeyManager
	ec_vss_km  ecdsa.ECDSAKeyManager
	ec_sign_km ecdsa.ECDSAKeyManager
	vss_mgr    vss.VssKeyManager
	sign_d     ecdsa.ECDSAKeyManager
	sign_e     ecdsa.ECDSAKeyManager
	hash_mgr   hash.HashManager
	pl         *pool.Pool
}

func NewFROSTSign(
	signcfgmgr config.SignConfigManager,
	statemgr state.MPCStateManager,
	sigmgr result.EddsaSignatureManager,
	msgmgr message.MessageManager,
	bcstmgr message.MessageManager,
	ecdsa_km ecdsa.ECDSAKeyManager,
	ec_vss_km ecdsa.ECDSAKeyManager,
	ec_sign_km ecdsa.ECDSAKeyManager,
	vss_mgr vss.VssKeyManager,
	sign_d ecdsa.ECDSAKeyManager,
	sign_e ecdsa.ECDSAKeyManager,
	hash_mgr hash.HashManager,
	pl *pool.Pool) *FROSTSign {
	return &FROSTSign{
		signcfgmgr: signcfgmgr,
		sigmgr:     sigmgr,
		statemgr:   statemgr,
		msgmgr:     msgmgr,
		bcstmgr:    bcstmgr,
		ecdsa_km:   ecdsa_km,
		ec_vss_km:  ec_vss_km,
		ec_sign_km: ec_sign_km,
		vss_mgr:    vss_mgr,
		sign_d:     sign_d,
		sign_e:     sign_e,
		hash_mgr:   hash_mgr,
		pl:         pl,
	}
}

func (f *FROSTSign) Start(cfg config.SignConfig) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		info := round.Info{
			ProtocolID:       SIGN_CONFIG_PROTOCOL_ID,
			FinalRoundNumber: protocolRounds,
			SelfID:           cfg.SelfID(),
			PartyIDs:         cfg.PartyIDs(),
			Threshold:        cfg.Threshold(),
			Group:            cfg.Group(),
		}

		opts := keyopts.Options{}
		opts.Set("id", cfg.ID(), "partyid", info.SelfID)

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
		lagrange := polynomial.Lagrange(cfg.Group(), cfg.PartyIDs())
		for _, j := range helper.PartyIDs() {
			vssOpts := keyopts.Options{}
			vssOpts.Set("id", cfg.KeyID(), "partyid", "ROOT")
			vss, err := f.vss_mgr.GetSecrets(vssOpts)
			if err != nil {
				return nil, err
			}

			partyVSSOpts := keyopts.Options{}
			partyVSSOpts.Set("id", hex.EncodeToString(vss.SKI()), "partyid", string(j))

			vssShareKey, err := f.ec_vss_km.GetKey(partyVSSOpts)
			if err != nil {
				return nil, err
			}

			partyOpts := keyopts.Options{}
			partyOpts.Set("id", cfg.ID(), "partyid", string(j))
			clonedj := vssShareKey.CloneByMultiplier(lagrange[j])
			if _, err := f.ec_sign_km.ImportKey(clonedj, partyOpts); err != nil {
				return nil, err
			}
		}

		if err := f.signcfgmgr.ImportConfig(cfg); err != nil {
			return nil, err
		}

		return &round1{
			Helper:     helper,
			cfg:        cfg,
			statemgr:   f.statemgr,
			sigmgr:     f.sigmgr,
			msgmgr:     f.msgmgr,
			bcstmgr:    f.bcstmgr,
			ecdsa_km:   f.ecdsa_km,
			ec_vss_km:  f.ec_vss_km,
			ec_sign_km: f.ec_sign_km,
			vss_mgr:    f.vss_mgr,
			sign_d:     f.sign_d,
			sign_e:     f.sign_e,
			hash_mgr:   f.hash_mgr,
		}, nil
	}
}

func (f *FROSTSign) GetRound(keyID string) (round.Session, error) {
	cfg, err := f.signcfgmgr.GetConfig(keyID)
	if err != nil {
		return nil, errors.WithMessage(err, "frost_sign: failed to get config")
	}

	info := round.Info{
		ProtocolID:       SIGN_CONFIG_PROTOCOL_ID,
		SelfID:           cfg.SelfID(),
		PartyIDs:         cfg.PartyIDs(),
		Threshold:        cfg.Threshold(),
		Group:            cfg.Group(),
		FinalRoundNumber: protocolRounds,
	}
	// instantiate a new hasher for new sign session
	opts := keyopts.Options{}
	opts.Set("id", cfg.ID(), "partyid", string(info.SelfID))
	h := f.hash_mgr.NewHasher(cfg.ID(), opts)

	// generate new helper for new sign session
	helper, err := round.NewSession(cfg.ID(), info, nil, f.pl, h)
	if err != nil {
		return nil, fmt.Errorf("frost_sign: %w", err)
	}

	state, err := f.statemgr.Get(keyID)
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
			ecdsa_km:   f.ecdsa_km,
			ec_vss_km:  f.ec_vss_km,
			ec_sign_km: f.ec_sign_km,
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
			ecdsa_km:   f.ecdsa_km,
			ec_vss_km:  f.ec_vss_km,
			ec_sign_km: f.ec_sign_km,
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
			ecdsa_km:   f.ecdsa_km,
			ec_vss_km:  f.ec_vss_km,
			ec_sign_km: f.ec_sign_km,
			vss_mgr:    f.vss_mgr,
			sign_d:     f.sign_d,
			sign_e:     f.sign_e,
			hash_mgr:   f.hash_mgr,
		}, nil
	default:
		return nil, errors.New("frost_sign: invalid round number")
	}
}

func (f *FROSTSign) StoreBroadcastMessage(keyID string, msg round.Message) error {
	r, err := f.GetRound(keyID)
	if err != nil {
		return errors.WithMessage(err, "frost_sign: failed to get round")
	}

	if err := r.StoreBroadcastMessage(msg); err != nil {
		return errors.WithMessage(err, "frost_sign: failed to store message")
	}

	return nil
}

func (f *FROSTSign) StoreMessage(keyID string, msg round.Message) error {
	r, err := f.GetRound(keyID)
	if err != nil {
		return errors.WithMessage(err, "frost_sign: failed to get round")
	}

	if err := r.StoreMessage(msg); err != nil {
		return errors.WithMessage(err, "frost_sign: failed to store message")
	}

	return nil
}

func (f *FROSTSign) Finalize(out chan<- *round.Message, keyID string) (round.Session, error) {
	r, err := f.GetRound(keyID)
	if err != nil {
		return nil, errors.WithMessage(err, "frost_sign: failed to get round")
	}

	return r.Finalize(out)
}
