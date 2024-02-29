package ecdsa

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
	comm_ecdsa "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
	zksch "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/zk-schnorr"
)

type Config struct {
	Group curve.Curve
}

type ECDSAKeyManager struct {
	keystore     keystore.Keystore
	schnorrstore keystore.Keystore
	cfg          *Config
}

func NewECDSAKeyManager(store keystore.Keystore, schnorrstore keystore.Keystore, cfg *Config) *ECDSAKeyManager {
	return &ECDSAKeyManager{
		keystore: store,
		cfg:      cfg,
	}
}

func (mgr *ECDSAKeyManager) GenerateKey() (comm_ecdsa.ECDSAKey, error) {
	// Generate a new ECDSA key pair
	sk, pk := sample.ScalarPointPair(rand.Reader, mgr.cfg.Group)

	// serialize key to store to the keystore
	key := NewECDSAKey(sk, pk, mgr.cfg.Group)
	decoded, err := key.Bytes()
	if err != nil {
		return ECDSAKey{}, err
	}

	// get key SKI and encode it to hex string as keyID
	ski := key.SKI()
	keyID := hex.EncodeToString(ski)

	// import the decoded key to the keystore with keyID
	if err := mgr.keystore.Import(keyID, decoded); err != nil {
		return ECDSAKey{}, err
	}

	// return the key pair
	return key.withZKSchnorr(
		zksch.NewZKSchnorr(mgr.schnorrstore.WithKeyID(keyID)),
	), nil
}

func (mgr *ECDSAKeyManager) ImportKey(key comm_ecdsa.ECDSAKey) error {
	// decode the key
	kb, err := key.Bytes()
	if err != nil {
		return err
	}

	// get key SKI and encode it to hex string as keyID
	ski := key.SKI()
	keyID := hex.EncodeToString(ski)

	// import the decoded key to the keystore with keyID
	if err := mgr.keystore.Import(keyID, kb); err != nil {
		return err
	}

	return nil
}

func (mgr *ECDSAKeyManager) GetKey(ski []byte) (comm_ecdsa.ECDSAKey, error) {
	// get the key from the keystore
	keyID := hex.EncodeToString(ski)
	decoded, err := mgr.keystore.Get(keyID)
	if err != nil {
		return ECDSAKey{}, err
	}

	// decode the key
	k, err := fromBytes(decoded)
	if err != nil {
		return ECDSAKey{}, err
	}

	return k.withZKSchnorr(
		zksch.NewZKSchnorr(mgr.schnorrstore.WithKeyID(keyID)),
	), err
}
