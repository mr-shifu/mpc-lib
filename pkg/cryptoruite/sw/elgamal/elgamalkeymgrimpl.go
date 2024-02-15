package elgamal

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"

	"github.com/mr-shifu/mpc-lib/core/elgamal"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
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

func (mgr *ElgamalKeyManager) GenerateKeyPair() (ElgamalKey, error) {
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
	if err := mgr.keystore.Import(keyID, decoded); err != nil {
		return ElgamalKey{}, err
	}

	// return the key pair
	return key, nil
}

func (mgr *ElgamalKeyManager) GetKey(ski []byte) ElgamalKey {
	// get the key from the keystore
	keyID := hex.EncodeToString(ski)
	decoded, err := mgr.keystore.Get(keyID)
	if err != nil {
		return ElgamalKey{}
	}

	// decode the key
	k, err := fromBytes(decoded)
	if err != nil {
		return ElgamalKey{}
	}

	return k
}

func (mgr *ElgamalKeyManager) Encrypt(ski []byte, message curve.Scalar) ([]byte, curve.Scalar) {
	k := mgr.GetKey(ski)
	ct, nonce := elgamal.Encrypt(k.publicKey, message)

	var buf bytes.Buffer
	if _, err := ct.WriteTo(&buf); err != nil {
		return nil, nil
	}

	return buf.Bytes(), nonce
}
