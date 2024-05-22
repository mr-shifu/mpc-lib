package keygen

import (
	"fmt"

	"github.com/pkg/errors"

	"github.com/mr-shifu/mpc-lib/core/pool"
	"github.com/mr-shifu/mpc-lib/core/protocol"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/commitment"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/rid"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/vss"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	mpc_config "github.com/mr-shifu/mpc-lib/pkg/mpc/common/config"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/message"
	mpc_state "github.com/mr-shifu/mpc-lib/pkg/mpc/common/state"
)

const (
	Rounds                    round.Number = 3
	KEYGEN_THRESHOLD_PROTOCOL string       = "frost/keygen-threshold"
)

type FROSTKeygen struct {
	configmgr   mpc_config.KeyConfigManager
	statemgr    mpc_state.MPCStateManager
	msgmgr      message.MessageManager
	bcstmgr     message.MessageManager
	ecdsa_km    ecdsa.ECDSAKeyManager
	ec_vss_km   ecdsa.ECDSAKeyManager
	vss_mgr     vss.VssKeyManager
	chainKey_km rid.RIDManager
	hash_mgr    hash.HashManager
	commit_mgr  commitment.CommitmentManager
	pl          *pool.Pool
}

func NewFROSTKeygen(
	keyconfigmgr mpc_config.KeyConfigManager,
	keystatmgr mpc_state.MPCStateManager,
	msgmgr message.MessageManager,
	bcstmgr message.MessageManager,
	ecdsa ecdsa.ECDSAKeyManager,
	ec_vss_km ecdsa.ECDSAKeyManager,
	vss_mgr vss.VssKeyManager,
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
		ecdsa_km:    ecdsa,
		ec_vss_km:   ec_vss_km,
		vss_mgr:     vss_mgr,
		chainKey_km: chainKey,
		hash_mgr:    hash_mgr,
		commit_mgr:  commit_mgr,
		pl:          pl,
	}
}

func (m *FROSTKeygen) Start(cfg mpc_config.KeyConfig) protocol.StartFunc {
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

		if err := m.configmgr.ImportConfig(cfg); err != nil {
			return nil, errors.WithMessage(err, "keygen: failed to import config")
		}

		// instantiate a new hasher for new keygen session
		opts := keyopts.Options{}
		opts.Set("id", cfg.ID(), "partyid", string(info.SelfID))
		h := m.hash_mgr.NewHasher(cfg.ID(), opts)

		// generate new helper for new keygen session
		helper, err := round.NewSession(cfg.ID(), info, sessionID, m.pl, h)
		if err != nil {
			return nil, fmt.Errorf("keygen: %w", err)
		}

		if err := m.statemgr.NewState(cfg.ID()); err != nil {
			return nil, err
		}

		return &round1{
			Helper:      helper,
			configmgr:   m.configmgr,
			statemgr:    m.statemgr,
			msgmgr:      m.msgmgr,
			bcstmgr:     m.bcstmgr,
			ec_km:       m.ecdsa_km,
			ec_vss_km:   m.ec_vss_km,
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
			ec_km:       m.ecdsa_km,
			ec_vss_km:   m.ec_vss_km,
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
			ec_km:       m.ecdsa_km,
			ec_vss_km:   m.ec_vss_km,
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
			ec_km:       m.ecdsa_km,
			ec_vss_km:   m.ec_vss_km,
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

	if err := r.VerifyMessage(msg); err != nil {
		return errors.WithMessage(err, "keygen: invalid message")
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

	if err := r.VerifyMessage(msg); err != nil {
		return errors.WithMessage(err, "keygen: invalid message")
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