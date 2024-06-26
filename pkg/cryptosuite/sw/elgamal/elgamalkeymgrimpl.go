package elgamal

import (
	"crypto/rand"
	"encoding/hex"
	"errors"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
	cs_elgamal "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/elgamal"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
)

type Config struct {
	Group curve.Curve
}

type ElgamalKeyManager struct {
	keystore keystore.Keystore
	cfg      *Config
}

func NewElgamalKeyManager(store keystore.Keystore, cfg *Config) *ElgamalKeyManager {
	return &ElgamalKeyManager{
		keystore: store,
		cfg:      cfg,
	}
}

func (mgr *ElgamalKeyManager) GenerateKey(opts keyopts.Options) (cs_elgamal.ElgamalKey, error) {
	// Generate a new ElGamal key pair
	sk, pk := sample.ScalarPointPair(rand.Reader, mgr.cfg.Group)

	// serialize key to store to the keystore
	key := ElgamalKey{sk, pk, mgr.cfg.Group}
	decoded, err := key.Bytes()
	if err != nil {
		return ElgamalKey{}, err
	}

	// get key SKI and encode it to hex string as keyID
	ski := key.SKI()
	keyID := hex.EncodeToString(ski)

	// import the decoded key to the keystore with keyID
	if err := mgr.keystore.Import(keyID, decoded, opts); err != nil {
		return ElgamalKey{}, err
	}

	// return the key pair
	return key, nil
}

func (mgr *ElgamalKeyManager) ImportKey(raw interface{}, opts keyopts.Options) (cs_elgamal.ElgamalKey, error) {
	var err error
	var key ElgamalKey

	switch raw := raw.(type) {
	case []byte:
		key, err = fromBytes(raw)
		if err != nil {
			return ElgamalKey{}, err
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
		return ElgamalKey{}, err
	}

	return key, err
}

func (mgr *ElgamalKeyManager) GetKey(opts keyopts.Options) (cs_elgamal.ElgamalKey, error) {
	// get the key from the keystore
	decoded, err := mgr.keystore.Get(opts)
	if err != nil {
		return ElgamalKey{}, err
	}

	// decode the key
	k, err := fromBytes(decoded)
	if err != nil {
		return ElgamalKey{}, err
	}

	return k, err
}

func (mgr *ElgamalKeyManager) Encrypt(message curve.Scalar, opts keyopts.Options) ([]byte, curve.Scalar, error) {
	k, err := mgr.GetKey(opts)
	if err != nil {
		return nil, nil, err
	}
	if k == (ElgamalKey{}) {
		return nil, nil, errors.New("key not found")
	}
	return k.Encrypt(message)
}
