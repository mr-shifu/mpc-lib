package elgamal

import (
	"bytes"
	"crypto/sha256"
	"errors"

	"github.com/fxamacker/cbor/v2"
	"github.com/mr-shifu/mpc-lib/core/elgamal"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	cs_elgamal "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/elgamal"
)

var (
	ErrInvalidKey = errors.New("invalid key")
)

type ElgamalKey struct {
	secretKey curve.Scalar
	publicKey curve.Point
	group     curve.Curve
}

type rawElgamalKey struct {
	Group  string
	Secret []byte
	Public []byte
}

func (key ElgamalKey) Bytes() ([]byte, error) {
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

func (key ElgamalKey) SKI() []byte {
	raw, err := key.publicKey.MarshalBinary()
	if err != nil {
		return nil
	}
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

func (key ElgamalKey) Private() bool {
	return key.secretKey != nil
}

func (key ElgamalKey) PublicKey() cs_elgamal.ElgamalKey {
	return ElgamalKey{nil, key.publicKey, key.group}
}

func (key ElgamalKey) PublicKeyRaw() curve.Point {
	return key.publicKey
}

func (key ElgamalKey) Encrypt(message curve.Scalar) ([]byte, curve.Scalar, error) {
	ct, nonce := elgamal.Encrypt(key.publicKey, message)

	var buf bytes.Buffer
	if _, err := ct.WriteTo(&buf); err != nil {
		return nil, nil, err
	}

	return buf.Bytes(), nonce, nil
}

func fromBytes(data []byte) (ElgamalKey, error) {
	key := ElgamalKey{}

	raw := &rawElgamalKey{}
	if err := cbor.Unmarshal(data, raw); err != nil {
		return ElgamalKey{}, err
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
			return ElgamalKey{}, err
		}
		key.secretKey = secret
	}

	pub := group.NewPoint()
	if err := pub.UnmarshalBinary(raw.Public); err != nil {
		return ElgamalKey{}, err
	}
	key.publicKey = pub

	return key, nil
}
