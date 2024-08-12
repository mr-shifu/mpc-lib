package keygen

import (
	"fmt"

	"github.com/mr-shifu/mpc-lib/core/pool"
	"github.com/mr-shifu/mpc-lib/core/protocol"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/paillier"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/pedersen"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/rid"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/vss"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/commitment"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/elgamal"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	mpc_config "github.com/mr-shifu/mpc-lib/pkg/mpc/common/config"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/message"
	mpc_state "github.com/mr-shifu/mpc-lib/pkg/mpc/common/state"
)

const Rounds round.Number = 5

type MPCKeygen struct {
	configmgr   mpc_config.KeyConfigManager
	statemgr    mpc_state.MPCStateManager
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
}

func NewMPCKeygen(
	keyconfigmgr mpc_config.KeyConfigManager,
	keystatmgr mpc_state.MPCStateManager,
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
	}
}

func (m *MPCKeygen) Start(cfg mpc_config.KeyConfig, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (_ round.Session, err error) {
		info := round.Info{
			ProtocolID:       "cmp/keygen",
			SelfID:           cfg.SelfID(),
			PartyIDs:         cfg.PartyIDs(),
			Threshold:        cfg.Threshold(),
			Group:            cfg.Group(),
			FinalRoundNumber: Rounds,
		}

		// m.keys[keyID] = info
		opts := keyopts.Options{}
		opts.Set("id", cfg.ID(), "partyid", string(info.SelfID))
		h := m.hash_mgr.NewHasher(cfg.ID(), opts)

		helper, err := round.NewSession(cfg.ID(), info, sessionID, pl, h)
		if err != nil {
			return nil, fmt.Errorf("keygen: %w", err)
		}

		// sample fᵢ(X) deg(fᵢ) = t, fᵢ(0) = secretᵢ
		key, err := m.ecdsa_km.GenerateKey(opts)
		if err != nil {
			return nil, fmt.Errorf("keygen: %w", err)
		}
		if err := key.GenerateVSSSecrets(helper.Threshold(), opts); err != nil {
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
