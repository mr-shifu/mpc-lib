package elgamal

import (
	"bytes"
	"crypto/sha256"
	"errors"

	"github.com/mr-shifu/mpc-lib/core/elgamal"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
)

var (
	ErrInvalidKey = errors.New("invalid key")
)

type ElgamalKey struct {
	secretKey curve.Scalar
	publicKey curve.Point
	group     curve.Curve
}

func (key *ElgamalKey) Bytes() ([]byte, error) {
	sk, err := key.secretKey.MarshalBinary()
	if err != nil {
		return nil, err
	}
	pk, err := key.publicKey.MarshalBinary()
	if err != nil {
		return nil, err
	}
	gn := key.group.Name()

	buf := make([]byte, 0)
	buf = append(buf, uint8(len(gn)))
	buf = append(buf, []byte(gn)...)
	buf = append(buf, uint8(len(pk)))
	buf = append(buf, pk...)
	buf = append(buf, uint8(len(sk)))
	buf = append(buf, sk...)

	return buf, nil
}

func (key *ElgamalKey) SKI() []byte {
	raw, err := key.publicKey.MarshalBinary()
	if err != nil {
		return nil
	}
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

func (key *ElgamalKey) Private() bool {
	return key.secretKey != nil
}

func (key *ElgamalKey) PublicKey() ElgamalKey {
	return ElgamalKey{nil, key.publicKey, key.group}
}

func (key *ElgamalKey) Encrypt(message curve.Scalar) ([]byte, curve.Scalar, error) {
	ct, nonce := elgamal.Encrypt(key.publicKey, message)

	var buf bytes.Buffer
	if _, err := ct.WriteTo(&buf); err != nil {
		return nil, nil, err
	}

	return buf.Bytes(), nonce, nil
}

func fromBytes(data []byte) (ElgamalKey, error) {
	if len(data) < 2 {
		return ElgamalKey{}, ErrInvalidKey
	}

	gnLen := int(data[0])
	if len(data) < 2+gnLen {
		return ElgamalKey{}, ErrInvalidKey
	}
	gn := string(data[1 : 1+gnLen])
	var group curve.Curve
	switch gn {
	case "secp256k1":
		group = curve.Secp256k1{}
	}

	pkLen := int(data[1+gnLen])
	if len(data) < 2+gnLen+pkLen {
		return ElgamalKey{}, ErrInvalidKey
	}
	pk := group.NewPoint()
	if err := pk.UnmarshalBinary(data[2+gnLen : 2+gnLen+pkLen]); err != nil {
		return ElgamalKey{}, err
	}

	skLen := int(data[2+gnLen+pkLen])
	if len(data) < 2+gnLen+pkLen+skLen {
		return ElgamalKey{}, ErrInvalidKey
	}
	sk := group.NewScalar()
	if err := sk.UnmarshalBinary(data[3+gnLen+pkLen:]); err != nil {
		return ElgamalKey{}, err
	}

	return ElgamalKey{sk, pk, group}, nil
}
