package ecdsa

import (
	"crypto/sha256"
	"errors"

	"github.com/fxamacker/cbor/v2"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss"
	zksch "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/zk-schnorr"
)

var (
	ErrInvalidKey = errors.New("invalid key")
)

type ECDSAKeyImpl struct {
	// Private key
	priv curve.Scalar

	// Public key
	pub curve.Point

	// group
	group curve.Curve

	zks *zksch.ZKSchnorr

	vssmgr vss.VssKeyManager
}

type rawECDSAKey struct {
	Group string
	Priv  []byte
	Pub   []byte
}

func NewKey(priv curve.Scalar, pub curve.Point, group curve.Curve) *ECDSAKeyImpl {
	return &ECDSAKeyImpl{
		priv:  priv,
		pub:   pub,
		group: group,
	}
}

func (key *ECDSAKeyImpl) Bytes() ([]byte, error) {
	raw := &rawECDSAKey{}

	raw.Group = key.group.Name()

	pub, err := key.pub.MarshalBinary()
	if err != nil {
		return nil, err
	}
	raw.Pub = pub

	if key.priv != nil {
		priv, err := key.priv.MarshalBinary()
		if err != nil {
			return nil, err
		}
		raw.Priv = priv
	}
	return cbor.Marshal(raw)
}

func (key *ECDSAKeyImpl) SKI() []byte {
	raw, err := key.pub.MarshalBinary()
	if err != nil {
		return nil
	}
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

func (key *ECDSAKeyImpl) Private() bool {
	return key.priv != nil
}

func (key *ECDSAKeyImpl) PublicKey() ECDSAKey {
	return NewKey(nil, key.pub, key.group)
}

func (key *ECDSAKeyImpl) Group() curve.Curve {
	return key.group
}

func (key *ECDSAKeyImpl) PublicKeyRaw() curve.Point {
	return key.pub
}

func (key *ECDSAKeyImpl) withZKSchnorr(zks *zksch.ZKSchnorr) *ECDSAKeyImpl {
	key.zks = zks
	return key
}

func (key *ECDSAKeyImpl) withVSSKeyMgr(vssmgr vss.VssKeyManager) *ECDSAKeyImpl {
	key.vssmgr = vssmgr
	return key
}

func fromBytes(data []byte) (*ECDSAKeyImpl, error) {
	key := &ECDSAKeyImpl{}

	raw := &rawECDSAKey{}
	if err := cbor.Unmarshal(data, raw); err != nil {
		return nil, err
	}

	var group curve.Curve
	switch raw.Group {
	case "secp256k1":
		group = curve.Secp256k1{}
	}
	key.group = group

	if len(raw.Priv) > 0 {
		priv := group.NewScalar()
		if err := priv.UnmarshalBinary(raw.Priv); err != nil {
			return nil, err
		}
		key.priv = priv
	}

	pub := group.NewPoint()
	if err := pub.UnmarshalBinary(raw.Pub); err != nil {
		return nil, err
	}
	key.pub = pub

	return key, nil
}
