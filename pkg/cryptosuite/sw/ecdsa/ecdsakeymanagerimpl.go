package ecdsa

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
	comm_ecdsa "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss"
	zksch "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/zk-schnorr"
)

type Config struct {
	Group curve.Curve
}

type ECDSAKeyManager struct {
	keystore     keystore.Keystore
	schnorrstore keystore.Keystore
	vssmgr       vss.VssKeyManager
	cfg          *Config
}

func NewECDSAKeyManager(
	store keystore.Keystore,
	schnorrstore keystore.Keystore,
	vssmgr vss.VssKeyManager,
	cfg *Config) *ECDSAKeyManager {
	return &ECDSAKeyManager{
		keystore:     store,
		schnorrstore: schnorrstore,
		vssmgr:       vssmgr,
		cfg:          cfg,
	}
}

func (mgr *ECDSAKeyManager) NewKey(priv curve.Scalar, pub curve.Point, group curve.Curve) comm_ecdsa.ECDSAKey {
	return NewECDSAKey(priv, pub, group)
}

func (mgr *ECDSAKeyManager) GenerateKey(opts keyopts.Options) (comm_ecdsa.ECDSAKey, error) {
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
	if err := mgr.keystore.Import(keyID, decoded, opts); err != nil {
		return ECDSAKey{}, err
	}

	// return the key pair
	return key.
		withZKSchnorr(zksch.NewZKSchnorr(mgr.schnorrstore.KeyAccessor(keyID, opts))).
		withVSSKeyMgr(mgr.vssmgr), nil
}

func (mgr *ECDSAKeyManager) ImportKey(raw interface{}, opts keyopts.Options) (comm_ecdsa.ECDSAKey, error) {
	var err error
	var key ECDSAKey

	switch raw := raw.(type) {
	case []byte:
		key, err = fromBytes(raw)
		if err != nil {
			return ECDSAKey{}, err
		}
	case ECDSAKey:
		key = raw
	}

	// decode the key
	kb, err := key.Bytes()
	if err != nil {
		return nil, err
	}

	// get key SKI and encode it to hex string as keyID
	ski := key.SKI()
	keyID := hex.EncodeToString(ski)

	// import the decoded key to the keystore with keyID
	if err := mgr.keystore.Import(keyID, kb, opts); err != nil {
		return nil, err
	}

	return key.
		withZKSchnorr(zksch.NewZKSchnorr(mgr.schnorrstore.KeyAccessor(keyID, opts))).
		withVSSKeyMgr(mgr.vssmgr), nil
}

func (mgr *ECDSAKeyManager) GetKey(opts keyopts.Options) (comm_ecdsa.ECDSAKey, error) {
	// get the key from the keystore
	// keyID := hex.EncodeToString(ski)
	decoded, err := mgr.keystore.Get(opts)
	if err != nil {
		return ECDSAKey{}, err
	}

	// decode the key
	k, err := fromBytes(decoded)
	if err != nil {
		return ECDSAKey{}, err
	}

	// get key SKI and encode it to hex string as keyID
	ski := k.SKI()
	keyID := hex.EncodeToString(ski)

	return k.
		withZKSchnorr(zksch.NewZKSchnorr(mgr.schnorrstore.KeyAccessor(keyID, opts))).
		withVSSKeyMgr(mgr.vssmgr), nil
}
