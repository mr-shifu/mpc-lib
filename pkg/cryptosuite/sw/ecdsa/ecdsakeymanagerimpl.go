package ecdsa

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss"
	zksch "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/zk-schnorr"
	"github.com/pkg/errors"
)

type Config struct {
	Group curve.Curve
}

type ECDSAKeyManagerImpl struct {
	keystore     keystore.Keystore
	schnorrstore keystore.Keystore
	vssmgr       vss.VssKeyManager
	cfg          *Config
}

func NewECDSAKeyManager(
	store keystore.Keystore,
	schnorrstore keystore.Keystore,
	vssmgr vss.VssKeyManager,
	cfg *Config) *ECDSAKeyManagerImpl {
	return &ECDSAKeyManagerImpl{
		keystore:     store,
		schnorrstore: schnorrstore,
		vssmgr:       vssmgr,
		cfg:          cfg,
	}
}

func (mgr *ECDSAKeyManagerImpl) GenerateKey(opts keyopts.Options) (ECDSAKey, error) {
	// Generate a new ECDSA key pair
	sk, pk := sample.ScalarPointPair(rand.Reader, mgr.cfg.Group)

	// serialize key to store to the keystore
	key := NewKey(sk, pk, mgr.cfg.Group)
	decoded, err := key.Bytes()
	if err != nil {
		return nil, err
	}

	// get key SKI and encode it to hex string as keyID
	ski := key.SKI()
	keyID := hex.EncodeToString(ski)

	// import the decoded key to the keystore with keyID
	if err := mgr.keystore.Import(keyID, decoded, opts); err != nil {
		return nil, err
	}

	// return the key pair
	return key.
		withZKSchnorr(zksch.NewZKSchnorr(mgr.schnorrstore.KeyAccessor(keyID, opts))).
		withVSSKeyMgr(mgr.vssmgr), nil
}

func (mgr *ECDSAKeyManagerImpl) ImportKey(raw interface{}, opts keyopts.Options) (ECDSAKey, error) {
	var err error
	key := &ECDSAKeyImpl{}

	switch raw := raw.(type) {
	case []byte:
		key, err = fromBytes(raw)
		if err != nil {
			return nil, err
		}
	case *ECDSAKeyImpl:
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

func (mgr *ECDSAKeyManagerImpl) GetKey(opts keyopts.Options) (ECDSAKey, error) {
	// get the key from the keystore
	// keyID := hex.EncodeToString(ski)
	decoded, err := mgr.keystore.Get(opts)
	if err != nil {
		return nil, err
	}

	// decode the key
	k, err := fromBytes(decoded)
	if err != nil {
		return nil, err
	}

	// get key SKI and encode it to hex string as keyID
	ski := k.SKI()
	keyID := hex.EncodeToString(ski)

	return k.
		withZKSchnorr(zksch.NewZKSchnorr(mgr.schnorrstore.KeyAccessor(keyID, opts))).
		withVSSKeyMgr(mgr.vssmgr), nil
}

func (mgr *ECDSAKeyManagerImpl) SumKeys(optsList ...keyopts.Options) (ECDSAKey, error) {
	group := curve.Secp256k1{}
	priv := group.NewScalar()
	pub := group.NewPoint()

	for i := 0; i < len(optsList); i++ {
		opts := optsList[i]
		k, err := mgr.GetKey(opts)
		if err != nil {
			return nil, errors.WithMessage(err, "ed25519: failed to get key from keystore")
		}

		key, ok := k.(*ECDSAKeyImpl)
		if !ok {
			return nil, errors.New("ed25519: invalid key type")
		}

		if i == 0 {
			priv = key.priv
			pub = key.pub
			continue
		}

		priv = priv.Add(key.priv)
		pub = pub.Add(key.pub)
	}

	priv = group.NewScalar().SetNat(curve.MakeInt(priv).Mod(group.Order()))

	return NewKey(priv, pub, group), nil
}
