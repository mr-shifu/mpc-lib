package elgamal

import (
	"bytes"
	"crypto/sha256"
	"errors"

	"github.com/fxamacker/cbor/v2"
	"github.com/mr-shifu/mpc-lib/core/elgamal"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
)

var (
	ErrInvalidKey = errors.New("invalid key")
)

type ElgamalKeyImpl struct {
	secretKey curve.Scalar
	publicKey curve.Point
	group     curve.Curve
}

type rawElgamalKey struct {
	Group  string
	Secret []byte
	Public []byte
}

var _ ElgamalKey = (*ElgamalKeyImpl)(nil)

func (key ElgamalKeyImpl) Bytes() ([]byte, error) {
	raw := &rawElgamalKey{}

	raw.Group = key.group.Name()

	pub, err := key.publicKey.MarshalBinary()
	if err != nil {
		return nil, err
	}
	raw.Public = pub

	if key.Private() {
		priv, err := key.secretKey.MarshalBinary()
		if err != nil {
			return nil, err
		}
		raw.Secret = priv
	}
	return cbor.Marshal(raw)
}

func (key ElgamalKeyImpl) SKI() []byte {
	raw, err := key.publicKey.MarshalBinary()
	if err != nil {
		return nil
	}
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

func (key ElgamalKeyImpl) Private() bool {
	return key.secretKey != nil
}

func (key ElgamalKeyImpl) PublicKey() ElgamalKey {
	return ElgamalKeyImpl{nil, key.publicKey, key.group}
}

func (key ElgamalKeyImpl) PublicKeyRaw() curve.Point {
	return key.publicKey
}

func (key ElgamalKeyImpl) Encrypt(message curve.Scalar) ([]byte, curve.Scalar, error) {
	ct, nonce := elgamal.Encrypt(key.publicKey, message)

	var buf bytes.Buffer
	if _, err := ct.WriteTo(&buf); err != nil {
		return nil, nil, err
	}

	return buf.Bytes(), nonce, nil
}

func fromBytes(data []byte) (ElgamalKeyImpl, error) {
	key := ElgamalKeyImpl{}

	raw := &rawElgamalKey{}
	if err := cbor.Unmarshal(data, raw); err != nil {
		return ElgamalKeyImpl{}, err
	}

	var group curve.Curve
	switch raw.Group {
	case "secp256k1":
		group = curve.Secp256k1{}
	}
	key.group = group

	if len(raw.Secret) > 0 {
		secret := group.NewScalar()
		if err := secret.UnmarshalBinary(raw.Secret); err != nil {
			return ElgamalKeyImpl{}, err
		}
		key.secretKey = secret
	}

	pub := group.NewPoint()
	if err := pub.UnmarshalBinary(raw.Public); err != nil {
		return ElgamalKeyImpl{}, err
	}
	key.publicKey = pub

	return key, nil
}
