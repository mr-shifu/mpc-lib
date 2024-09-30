package keygen

import (
	"fmt"

	"github.com/mr-shifu/mpc-lib/core/pool"
	"github.com/mr-shifu/mpc-lib/core/protocol"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/commitment"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/elgamal"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillier"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/pedersen"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/rid"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/config"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/message"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/state"
	"github.com/pkg/errors"
)

const Rounds round.Number = 5

type MPCKeygen struct {
	configmgr   config.KeyConfigManager
	statemgr    state.MPCStateManager
	msgmgr      message.MessageManager
	bcstmgr     message.MessageManager
	elgamal_km  elgamal.ElgamalKeyManager
	paillier_km paillier.PaillierKeyManager
	pedersen_km pedersen.PedersenKeyManager
	ecdsa_km    ecdsa.ECDSAKeyManager
	ec_vss_km   ecdsa.ECDSAKeyManager
	vss_mgr     vss.VssKeyManager
	rid_km      rid.RIDManager
	chainKey_km rid.RIDManager
	hash_mgr    hash.HashManager
	commit_mgr  commitment.CommitmentManager
	pl          *pool.Pool
}

func NewMPCKeygen(
	keyconfigmgr config.KeyConfigManager,
	keystatmgr state.MPCStateManager,
	msgmgr message.MessageManager,
	bcstmgr message.MessageManager,
	elgamal elgamal.ElgamalKeyManager,
	paillier paillier.PaillierKeyManager,
	pedersen pedersen.PedersenKeyManager,
	ecdsa ecdsa.ECDSAKeyManager,
	ec_vss_km ecdsa.ECDSAKeyManager,
	vss_mgr vss.VssKeyManager,
	rid rid.RIDManager,
	chainKey rid.RIDManager,
	hash_mgr hash.HashManager,
	commit_mgr commitment.CommitmentManager,
	pl *pool.Pool,
) *MPCKeygen {
	return &MPCKeygen{
		configmgr:   keyconfigmgr,
		statemgr:    keystatmgr,
		msgmgr:      msgmgr,
		bcstmgr:     bcstmgr,
		elgamal_km:  elgamal,
		paillier_km: paillier,
		pedersen_km: pedersen,
		ecdsa_km:    ecdsa,
		ec_vss_km:   ec_vss_km,
		vss_mgr:     vss_mgr,
		rid_km:      rid,
		chainKey_km: chainKey,
		hash_mgr:    hash_mgr,
		commit_mgr:  commit_mgr,
		pl:          pl,
	}
}

func (m *MPCKeygen) Start(cfg any) protocol.StartFunc {
	return func(sessionID []byte) (_ round.Session, err error) {
		cfg, ok := cfg.(config.KeyConfig)
		if !ok {
			return nil, errors.New("cmp.Keygen.Start: invalid config")
		}
		info := round.Info{
			ProtocolID:       "cmp/keygen",
			SelfID:           cfg.SelfID(),
			PartyIDs:         cfg.PartyIDs(),
			Threshold:        cfg.Threshold(),
			Group:            cfg.Group(),
			FinalRoundNumber: Rounds,
		}

		// m.keys[keyID] = info
		opts, err := keyopts.NewOptions().Set("id", cfg.ID(), "partyid", string(info.SelfID))
		if err != nil {
			return nil, errors.WithMessage(err, "cmp.Keygen.Start: failed to create options")
		}

		h := m.hash_mgr.NewHasher(cfg.ID(), opts)

		helper, err := round.NewSession(cfg.ID(), info, sessionID, m.pl, h)
		if err != nil {
			return nil, fmt.Errorf("keygen: %w", err)
		}

		// sample fᵢ(X) deg(fᵢ) = t, fᵢ(0) = secretᵢ
		if _, err = m.ecdsa_km.GenerateKey(opts); err != nil {
			return nil, fmt.Errorf("keygen: %w", err)
		}
		if _, err := m.ecdsa_km.GenerateVss(helper.Threshold(), opts); err != nil {
			return nil, fmt.Errorf("keygen: %w", err)
		}

		if err := m.configmgr.ImportConfig(cfg); err != nil {
			return nil, err
		}

		if err := m.statemgr.NewState(cfg.ID()); err != nil {
			return nil, err
		}

		return &round1{
			Helper:      helper,
			statemanger: m.statemgr,
			msgmgr:      m.msgmgr,
			bcstmgr:     m.bcstmgr,
			elgamal_km:  m.elgamal_km,
			paillier_km: m.paillier_km,
			pedersen_km: m.pedersen_km,
			ecdsa_km:    m.ecdsa_km,
			ec_vss_km:   m.ec_vss_km,
			vss_mgr:     m.vss_mgr,
			rid_km:      m.rid_km,
			chainKey_km: m.chainKey_km,
			commit_mgr:  m.commit_mgr,
		}, nil

	}
}

func (m *MPCKeygen) GetRound(keyID string) (round.Session, error) {
	cfg, err := m.configmgr.GetConfig(keyID)
	if err != nil {
		return nil, errors.WithMessage(err, "cmp.Keygen: failed to get config")
	}

	info := round.Info{
		ProtocolID:       "cmp/keygen",
		SelfID:           cfg.SelfID(),
		PartyIDs:         cfg.PartyIDs(),
		Threshold:        cfg.Threshold(),
		Group:            cfg.Group(),
		FinalRoundNumber: Rounds,
	}

	// generate new helper for new keygen session
	helper, err := round.ResumeSession(cfg.ID(), info, nil, m.pl, m.hash_mgr)
	if err != nil {
		return nil, fmt.Errorf("cmp.Keygen: %w", err)
	}

	state, err := m.statemgr.Get(keyID)
	if err != nil {
		return nil, errors.WithMessage(err, "cmp.Keygen: failed to get state")
	}
	rn := state.LastRound()
	switch rn {
	case 0:
		return &round1{
			Helper:      helper,
			statemanger: m.statemgr,
			msgmgr:      m.msgmgr,
			bcstmgr:     m.bcstmgr,
			elgamal_km:  m.elgamal_km,
			paillier_km: m.paillier_km,
			pedersen_km: m.pedersen_km,
			ecdsa_km:    m.ecdsa_km,
			ec_vss_km:   m.ec_vss_km,
			vss_mgr:     m.vss_mgr,
			rid_km:      m.rid_km,
			chainKey_km: m.chainKey_km,
			commit_mgr:  m.commit_mgr,
		}, nil
	case 1:
		return &round2{
			Helper:      helper,
			statemanger: m.statemgr,
			msgmgr:      m.msgmgr,
			bcstmgr:     m.bcstmgr,
			elgamal_km:  m.elgamal_km,
			paillier_km: m.paillier_km,
			pedersen_km: m.pedersen_km,
			ecdsa_km:    m.ecdsa_km,
			ec_vss_km:   m.ec_vss_km,
			vss_mgr:     m.vss_mgr,
			rid_km:      m.rid_km,
			chainKey_km: m.chainKey_km,
			commit_mgr:  m.commit_mgr,
		}, nil
	case 2:
		return &round3{
			Helper:      helper,
			statemanger: m.statemgr,
			msgmgr:      m.msgmgr,
			bcstmgr:     m.bcstmgr,
			elgamal_km:  m.elgamal_km,
			paillier_km: m.paillier_km,
			pedersen_km: m.pedersen_km,
			ecdsa_km:    m.ecdsa_km,
			ec_vss_km:   m.ec_vss_km,
			vss_mgr:     m.vss_mgr,
			rid_km:      m.rid_km,
			chainKey_km: m.chainKey_km,
			commit_mgr:  m.commit_mgr,
		}, nil
	case 3:
		return &round4{
			Helper:      helper,
			statemanger: m.statemgr,
			msgmgr:      m.msgmgr,
			bcstmgr:     m.bcstmgr,
			elgamal_km:  m.elgamal_km,
			paillier_km: m.paillier_km,
			pedersen_km: m.pedersen_km,
			ecdsa_km:    m.ecdsa_km,
			ec_vss_km:   m.ec_vss_km,
			vss_mgr:     m.vss_mgr,
			rid_km:      m.rid_km,
			chainKey_km: m.chainKey_km,
			commit_mgr:  m.commit_mgr,
		}, nil
	case 4:
		return &round5{
			Helper:      helper,
			statemanger: m.statemgr,
			msgmgr:      m.msgmgr,
			bcstmgr:     m.bcstmgr,
			elgamal_km:  m.elgamal_km,
			paillier_km: m.paillier_km,
			pedersen_km: m.pedersen_km,
			ecdsa_km:    m.ecdsa_km,
			ec_vss_km:   m.ec_vss_km,
			vss_mgr:     m.vss_mgr,
			rid_km:      m.rid_km,
			chainKey_km: m.chainKey_km,
			commit_mgr:  m.commit_mgr,
		}, nil
	default:
		return nil, errors.New("cmp.Keygen: invalid round number")
	}
}

func (m *MPCKeygen) StoreBroadcastMessage(keyID string, msg round.Message) error {
	r, err := m.GetRound(keyID)
	if err != nil {
		return errors.WithMessage(err, "cmp.Keygen: failed to get round")
	}

	if err := r.StoreBroadcastMessage(msg); err != nil {
		return errors.WithMessage(err, "cmp.Keygen: failed to store message")
	}

	return nil
}

func (m *MPCKeygen) StoreMessage(keyID string, msg round.Message) error {
	r, err := m.GetRound(keyID)
	if err != nil {
		return errors.WithMessage(err, "cmp.Keygen: failed to get round")
	}

	if err := r.StoreMessage(msg); err != nil {
		return errors.WithMessage(err, "cmp.Keygen: failed to store message")
	}

	return nil
}

func (m *MPCKeygen) Finalize(out chan<- *round.Message, keyID string) (round.Session, error) {
	r, err := m.GetRound(keyID)
	if err != nil {
		return nil, errors.WithMessage(err, "cmp.Keygen: failed to get round")
	}

	return r.Finalize(out)
}

func (m *MPCKeygen) CanFinalize(keyID string) (bool, error) {
	r, err := m.GetRound(keyID)
	if err != nil {
		return false, errors.WithMessage(err, "cmp.Keygen: failed to get round")
	}
	return r.CanFinalize(), nil
}

func (m *MPCKeygen) CanStoreMessage(keyID string, roundNumber int) (bool, error) {
	state, err := m.statemgr.Get(keyID)
	if err != nil {
		return false, errors.WithMessage(err, "cmp.Keygen: failed to get state")
	}
	rn := state.LastRound()
	if rn != roundNumber-1 {
		return false, nil
	}
	return true, nil
}
