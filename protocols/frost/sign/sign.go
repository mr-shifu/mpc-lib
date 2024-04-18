package sign

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/mr-shifu/mpc-lib/core/math/polynomial"
	"github.com/mr-shifu/mpc-lib/core/pool"
	"github.com/mr-shifu/mpc-lib/core/protocol"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/lib/types"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/config"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/state"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/message"
)

const (
	// Frost Sign with Threshold.
	protocolID = "frost/sign-threshold"
	// This protocol has 3 concrete rounds.
	protocolRounds round.Number = 3
)

type FROSTSign struct {
	signcfgmgr config.SignConfigManager
	statemgr   state.MPCStateManager
	msgmgr     message.MessageManager
	bcstmgr    message.MessageManager
	ecdsa_km   ecdsa.ECDSAKeyManager
	ec_vss_km  ecdsa.ECDSAKeyManager
	ec_sign_km ecdsa.ECDSAKeyManager
	vss_mgr    vss.VssKeyManager
	hash_mgr   hash.HashManager
}

func NewFROSTSign(
	signcfgmgr config.SignConfigManager,
	statemgr state.MPCStateManager,
	msgmgr message.MessageManager,
	bcstmgr message.MessageManager,
	ecdsa_km ecdsa.ECDSAKeyManager,
	ec_vss_km ecdsa.ECDSAKeyManager,
	ec_sign_km ecdsa.ECDSAKeyManager,
	vss_mgr vss.VssKeyManager,
	hash_mgr hash.HashManager) *FROSTSign {
	return &FROSTSign{
		signcfgmgr: signcfgmgr,
		statemgr:   statemgr,
		msgmgr:     msgmgr,
		bcstmgr:    bcstmgr,
		ecdsa_km:   ecdsa_km,
		ec_vss_km:  ec_vss_km,
		vss_mgr:    vss_mgr,
		hash_mgr:   hash_mgr,
	}
}

func (f *FROSTSign) Start(cfg config.SignConfig, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		info := round.Info{
			ProtocolID:       protocolID,
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
		helper, err := round.NewSession(cfg.ID(), info, sessionID, pl, h, types.SigningMessage(cfg.Message()))
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

		return nil, nil
	}
}
