package elgamal

import (
	"crypto/rand"
	"encoding/hex"
	"errors"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
)

type Config struct {
	Group curve.Curve
}

type ElgamalKeyManagerImpl struct {
	keystore keystore.Keystore
	cfg      *Config
}

var _ ElgamalKeyManager = (*ElgamalKeyManagerImpl)(nil)

func NewElgamalKeyManager(store keystore.Keystore, cfg *Config) *ElgamalKeyManagerImpl {
	return &ElgamalKeyManagerImpl{
		keystore: store,
		cfg:      cfg,
	}
}

func (mgr *ElgamalKeyManagerImpl) GenerateKey(opts keyopts.Options) (ElgamalKey, error) {
	// Generate a new ElGamal key pair
	sk, pk := sample.ScalarPointPair(rand.Reader, mgr.cfg.Group)

	// serialize key to store to the keystore
	key := ElgamalKeyImpl{sk, pk, mgr.cfg.Group}
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
	return key, nil
}

func (mgr *ElgamalKeyManagerImpl) ImportKey(raw interface{}, opts keyopts.Options) (ElgamalKey, error) {
	var err error
	var key ElgamalKey

	switch raw := raw.(type) {
	case []byte:
		key, err = fromBytes(raw)
		if err != nil {
			return nil, err
		}
	case ElgamalKey:
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

	return key, err
}

func (mgr *ElgamalKeyManagerImpl) GetKey(opts keyopts.Options) (ElgamalKey, error) {
	// get the key from the keystore
	decoded, err := mgr.keystore.Get(opts)
	if err != nil {
		return nil, err
	}

	// decode the key
	k, err := fromBytes(decoded)
	if err != nil {
		return nil, err
	}

	return k, err
}

func (mgr *ElgamalKeyManagerImpl) Encrypt(message curve.Scalar, opts keyopts.Options) ([]byte, curve.Scalar, error) {
	k, err := mgr.GetKey(opts)
	if err != nil {
		return nil, nil, err
	}
	if k == nil {
		return nil, nil, errors.New("key not found")
	}
	return k.Encrypt(message)
}
