package keygen

import (
	"fmt"

	"github.com/pkg/errors"

	"github.com/mr-shifu/mpc-lib/core/pool"
	"github.com/mr-shifu/mpc-lib/core/protocol"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/commitment"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/rid"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ed25519"
	vssed25519 "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss-ed25519"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/config"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/message"
	mpc_state "github.com/mr-shifu/mpc-lib/pkg/mpc/common/state"
)

const (
	Rounds                    round.Number = 3
	KEYGEN_THRESHOLD_PROTOCOL string       = "frost/keygen-threshold"
)

type FROSTKeygen struct {
	configmgr   config.KeyConfigManager
	statemgr    mpc_state.MPCStateManager
	msgmgr      message.MessageManager
	bcstmgr     message.MessageManager
	eddsa_km    ed25519.Ed25519KeyManager
	ed_vss_km   ed25519.Ed25519KeyManager
	vss_mgr     vssed25519.VssKeyManager
	chainKey_km rid.RIDManager
	hash_mgr    hash.HashManager
	commit_mgr  commitment.CommitmentManager
	pl          *pool.Pool
}

var _ protocol.Processor = (*FROSTKeygen)(nil)

func NewFROSTKeygen(
	keyconfigmgr config.KeyConfigManager,
	keystatmgr mpc_state.MPCStateManager,
	msgmgr message.MessageManager,
	bcstmgr message.MessageManager,
	eddsa_km ed25519.Ed25519KeyManager,
	ed_vss_km ed25519.Ed25519KeyManager,
	vss_mgr vssed25519.VssKeyManager,
	chainKey rid.RIDManager,
	hash_mgr hash.HashManager,
	commit_mgr commitment.CommitmentManager,
	pl *pool.Pool,
) *FROSTKeygen {
	return &FROSTKeygen{
		configmgr:   keyconfigmgr,
		statemgr:    keystatmgr,
		msgmgr:      msgmgr,
		bcstmgr:     bcstmgr,
		eddsa_km:    eddsa_km,
		ed_vss_km:   ed_vss_km,
		vss_mgr:     vss_mgr,
		chainKey_km: chainKey,
		hash_mgr:    hash_mgr,
		commit_mgr:  commit_mgr,
		pl:          pl,
	}
}

func (m *FROSTKeygen) Start(configs any) protocol.StartFunc {
	cfg, ok := configs.(config.KeyConfig)
	if !ok {
		return nil
	}

	return func(sessionID []byte) (_ round.Session, err error) {
		// TODO we should supprt taproot for next version
		info := round.Info{
			ProtocolID:       KEYGEN_THRESHOLD_PROTOCOL,
			SelfID:           cfg.SelfID(),
			PartyIDs:         cfg.PartyIDs(),
			Threshold:        cfg.Threshold(),
			Group:            cfg.Group(),
			FinalRoundNumber: Rounds,
		}

		// 1. if config already exists and the state is completed -> update state to refresh
		// otherwise import new config
		refresh := false
		state, err := m.statemgr.Get(cfg.ID())
		if err == nil {
			if state.Completed() {
				// we must refresh the key, update key state to Refresh
				refresh = true
			} else {
				// new request must be ignored as keygen is running
				return nil, fmt.Errorf("keygen: key genereation is still running")
			}
		}

		// 2. if NOT Refreshing -> Import configs for new key
		if !refresh {
			if err := m.configmgr.ImportConfig(cfg); err != nil {
				return nil, errors.WithMessage(err, "keygen: failed to import config")
			}
		}

		// 3. conform new option based on keygen or key refreshing
		var kid = cfg.ID()
		if refresh {
			kid = fmt.Sprintf("refresh-%s", cfg.ID())
		}
		opts, err := keyopts.NewOptions().Set("id", kid, "partyid", string(info.SelfID))
		if err != nil {
			return nil, errors.WithMessage(err, "keygen: failed to set options")
		}

		// 4. instantiate a new hasher for new keygen session
		h := m.hash_mgr.NewHasher(cfg.ID(), opts)

		// 5. generate new helper for new keygen session
		// ToDo we'd better to remove Helper or regenerate it from data store
		helper, err := round.NewSession(kid, info, sessionID, m.pl, h)
		if err != nil {
			return nil, fmt.Errorf("keygen: %w", err)
		}

		// 6. if keygen -> Import new state, otherwise, update state.refresh = true
		if !refresh {
			if err := m.statemgr.NewState(cfg.ID()); err != nil {
				return nil, err
			}
		} else {
			// ToDo Set state.Completed = false
			if err := m.statemgr.SetRefresh(cfg.ID(), true); err != nil {
				return nil, fmt.Errorf("keygen: failed to update key state to refresh state")
			}
		}

		return &round1{
			Helper:      helper,
			configmgr:   m.configmgr,
			statemgr:    m.statemgr,
			msgmgr:      m.msgmgr,
			bcstmgr:     m.bcstmgr,
			ed_km:       m.eddsa_km,
			ed_vss_km:   m.ed_vss_km,
			vss_mgr:     m.vss_mgr,
			chainKey_km: m.chainKey_km,
			commit_mgr:  m.commit_mgr,
		}, nil
	}
}

func (m *FROSTKeygen) GetRound(keyID string) (round.Session, error) {
	cfg, err := m.configmgr.GetConfig(keyID)
	if err != nil {
		return nil, errors.WithMessage(err, "keygen: failed to get config")
	}

	info := round.Info{
		ProtocolID:       KEYGEN_THRESHOLD_PROTOCOL,
		SelfID:           cfg.SelfID(),
		PartyIDs:         cfg.PartyIDs(),
		Threshold:        cfg.Threshold(),
		Group:            cfg.Group(),
		FinalRoundNumber: Rounds,
	}
	// instantiate a new hasher for new keygen session
	opts := keyopts.Options{}
	opts.Set("id", cfg.ID(), "partyid", string(info.SelfID))
	h := m.hash_mgr.NewHasher(cfg.ID(), opts)

	// generate new helper for new keygen session
	helper, err := round.NewSession(cfg.ID(), info, nil, m.pl, h)
	if err != nil {
		return nil, fmt.Errorf("keygen: %w", err)
	}

	state, err := m.statemgr.Get(keyID)
	if err != nil {
		return nil, errors.WithMessage(err, "keygen: failed to get state")
	}
	rn := state.LastRound()
	switch rn {
	case 0:
		return &round1{
			Helper:      helper,
			configmgr:   m.configmgr,
			statemgr:    m.statemgr,
			msgmgr:      m.msgmgr,
			bcstmgr:     m.bcstmgr,
			ed_km:       m.eddsa_km,
			ed_vss_km:   m.ed_vss_km,
			vss_mgr:     m.vss_mgr,
			chainKey_km: m.chainKey_km,
			commit_mgr:  m.commit_mgr,
		}, nil
	case 1:
		return &round2{
			Helper:      helper,
			configmgr:   m.configmgr,
			statemgr:    m.statemgr,
			msgmgr:      m.msgmgr,
			bcstmgr:     m.bcstmgr,
			ed_km:       m.eddsa_km,
			ed_vss_km:   m.ed_vss_km,
			vss_mgr:     m.vss_mgr,
			chainKey_km: m.chainKey_km,
			commit_mgr:  m.commit_mgr,
		}, nil
	case 2:
		return &round3{
			Helper:      helper,
			configmgr:   m.configmgr,
			statemgr:    m.statemgr,
			msgmgr:      m.msgmgr,
			bcstmgr:     m.bcstmgr,
			ed_km:       m.eddsa_km,
			ed_vss_km:   m.ed_vss_km,
			vss_mgr:     m.vss_mgr,
			chainKey_km: m.chainKey_km,
			commit_mgr:  m.commit_mgr,
		}, nil
	default:
		return nil, errors.New("keygen: invalid round number")
	}
}

func (m *FROSTKeygen) StoreBroadcastMessage(keyID string, msg round.Message) error {
	r, err := m.GetRound(keyID)
	if err != nil {
		return errors.WithMessage(err, "keygen: failed to get round")
	}

	if err := r.StoreBroadcastMessage(msg); err != nil {
		return errors.WithMessage(err, "keygen: failed to store message")
	}

	return nil
}

func (m *FROSTKeygen) StoreMessage(keyID string, msg round.Message) error {
	r, err := m.GetRound(keyID)
	if err != nil {
		return errors.WithMessage(err, "keygen: failed to get round")
	}

	if err := r.StoreMessage(msg); err != nil {
		return errors.WithMessage(err, "keygen: failed to store message")
	}

	return nil
}

func (m *FROSTKeygen) Finalize(out chan<- *round.Message, keyID string) (round.Session, error) {
	r, err := m.GetRound(keyID)
	if err != nil {
		return nil, errors.WithMessage(err, "keygen: failed to get round")
	}

	return r.Finalize(out)
}

func (m *FROSTKeygen) CanFinalize(keyID string) (bool, error) {
	r, err := m.GetRound(keyID)
	if err != nil {
		return false, errors.WithMessage(err, "keygen: failed to get round")
	}
	return r.CanFinalize(), nil
}
