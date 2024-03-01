package ecdsa

import (
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/vss"
)

func (key ECDSAKey) VSS() (vss.VssKey, error) {
	return key.vssmgr.GetSecrets(key.SKI())
}