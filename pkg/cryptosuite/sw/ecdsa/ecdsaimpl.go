package ecdsa

import (
	"crypto/sha256"
	"errors"

	"github.com/fxamacker/cbor/v2"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	comm_ecdsa "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss"
	zksch "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/zk-schnorr"
)

var (
	ErrInvalidKey = errors.New("invalid key")
)

type ECDSAKey struct {
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

func NewECDSAKey(priv curve.Scalar, pub curve.Point, group curve.Curve) ECDSAKey {
	return ECDSAKey{
		priv:  priv,
		pub:   pub,
		group: group,
	}
}

func (key ECDSAKey) Bytes() ([]byte, error) {
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

func (key ECDSAKey) SKI() []byte {
	raw, err := key.pub.MarshalBinary()
	if err != nil {
		return nil
	}
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

func (key ECDSAKey) Private() bool {
	return key.priv != nil
}

func (key ECDSAKey) PublicKey() comm_ecdsa.ECDSAKey {
	return NewECDSAKey(nil, key.pub, key.group)
}

func (key ECDSAKey) Group() curve.Curve {
	return key.group
}

func (key ECDSAKey) PublicKeyRaw() curve.Point {
	return key.pub
}

func (key ECDSAKey) withZKSchnorr(zks *zksch.ZKSchnorr) ECDSAKey {
	key.zks = zks
	return key
}

func (key ECDSAKey) withVSSKeyMgr(vssmgr vss.VssKeyManager) ECDSAKey {
	key.vssmgr = vssmgr
	return key
}

func fromBytes(data []byte) (ECDSAKey, error) {
	key := ECDSAKey{}

	raw := &rawECDSAKey{}
	if err := cbor.Unmarshal(data, raw); err != nil {
		return ECDSAKey{}, err
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
			return ECDSAKey{}, err
		}
		key.priv = priv
	}

	pub := group.NewPoint()
	if err := pub.UnmarshalBinary(raw.Pub); err != nil {
		return ECDSAKey{}, err
	}
	key.pub = pub

	return key, nil
}
