package ecdsa

import (
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/vss"
)

func (key ECDSAKey) VSS() (vss.VssKey, error) {
	return key.vssmgr.GetSecrets(key.SKI())
}

func (key ECDSAKey) GenerateVSSSecrets(degree int) error {
	_, err := key.vssmgr.GenerateSecrets(key.priv, degree)
	return err
}

func (key ECDSAKey) ImportVSSSecrets(exponents []byte) error {
	_, err := key.vssmgr.ImportSecrets(exponents)
	return err
}