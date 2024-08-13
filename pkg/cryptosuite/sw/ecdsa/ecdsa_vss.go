package ecdsa

import (
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
)

func (key ECDSAKey) VSS(opts keyopts.Options) (vss.VssKey, error) {
	return key.vssmgr.GetSecrets(opts)
}

func (key ECDSAKey) GenerateVSSSecrets(degree int, opts keyopts.Options) error {
	_, err := key.vssmgr.GenerateSecrets(key.priv, degree, opts)
	return err
}

// func (key ECDSAKey) ImportVSSSecrets(k vss.VssKey, opts keyopts.Options) error {
// 	_, err := key.vssmgr.ImportSecrets(k, opts)
// 	return err
// }
