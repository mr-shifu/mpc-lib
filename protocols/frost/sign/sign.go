package sign

import (
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss"
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
	statemgr  state.MPCStateManager
	msgmgr    message.MessageManager
	bcstmgr   message.MessageManager
	ecdsa_km  ecdsa.ECDSAKeyManager
	ec_vss_km ecdsa.ECDSAKeyManager
	vss_mgr   vss.VssKeyManager
	hash_mgr  hash.HashManager
}

func NewFROSTSign(statemgr state.MPCStateManager,
	msgmgr message.MessageManager,
	bcstmgr message.MessageManager,
	ecdsa_km ecdsa.ECDSAKeyManager,
	ec_vss_km ecdsa.ECDSAKeyManager,
	vss_mgr vss.VssKeyManager,
	hash_mgr hash.HashManager) *FROSTSign {
	return &FROSTSign{
		statemgr:  statemgr,
		msgmgr:    msgmgr,
		bcstmgr:   bcstmgr,
		ecdsa_km:  ecdsa_km,
		ec_vss_km: ec_vss_km,
		vss_mgr:   vss_mgr,
		hash_mgr:  hash_mgr,
	}
}
