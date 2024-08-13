package paillierencodedkey

import (
	"errors"

	"github.com/cronokirby/saferith"
	"github.com/fxamacker/cbor/v2"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/paillier"
)

var (
	ErrKeyNotFound = errors.New("paillierencodedkey: key not found")
)

type PaillierEncodedKeyImpl struct {
	group   curve.Curve
	secret  curve.Scalar
	encoded *paillier.Ciphertext
	nonce   *saferith.Nat
}

type rawPaillierEncodedKey struct {
	Group   string
	Secret  []byte
	Encoded []byte
	Nonce   []byte
}

var _ PaillierEncodedKey = (*PaillierEncodedKeyImpl)(nil)

func NewPaillierEncodedKeyImpl(secret curve.Scalar, encoded *paillier.Ciphertext, nonce *saferith.Nat, curve curve.Curve) PaillierEncodedKey {
	return &PaillierEncodedKeyImpl{
		group:   curve,
		secret:  secret,
		encoded: encoded,
		nonce:   nonce,
	}
}

func (k *PaillierEncodedKeyImpl) Bytes() ([]byte, error) {
	group := k.group.Name()

	raw := rawPaillierEncodedKey{
		Group: group,
	}

	if k.secret != nil {
		sk_bytes, err := k.secret.MarshalBinary()
		if err != nil {
			return nil, err
		}
		raw.Secret = sk_bytes
	}

	enc_bytes, err := k.encoded.MarshalBinary()
	if err != nil {
		return nil, err
	}
	raw.Encoded = enc_bytes

	if k.nonce != nil {
		nonce_bytes, err := k.nonce.MarshalBinary()
		if err != nil {
			return nil, err
		}
		raw.Nonce = nonce_bytes
	}

	return cbor.Marshal(raw)
}

func (k *PaillierEncodedKeyImpl) Secret() curve.Scalar {
	return k.secret
}

func (k *PaillierEncodedKeyImpl) Encoded() *paillier.Ciphertext {
	return k.encoded
}

func (k *PaillierEncodedKeyImpl) Nonce() *saferith.Nat {
	return k.nonce
}

func fromBytes(data []byte) (*PaillierEncodedKeyImpl, error) {
	var raw rawPaillierEncodedKey
	err := cbor.Unmarshal(data, &raw)
	if err != nil {
		return nil, err
	}

	var group curve.Curve
	switch raw.Group {
	case "secp256k1":
		group = curve.Secp256k1{}
	}

	k := &PaillierEncodedKeyImpl{
		group: group,
	}

	if raw.Secret != nil {
		sk := group.NewScalar()
		err = sk.UnmarshalBinary(raw.Secret)
		if err != nil {
			return nil, err
		}
		k.secret = sk
	}

	enc := &paillier.Ciphertext{}
	err = enc.UnmarshalBinary(raw.Encoded)
	if err != nil {
		return nil, err
	}
	k.encoded = enc

	nonce := new(saferith.Nat)
	err = nonce.UnmarshalBinary(raw.Nonce)
	if err != nil {
		return nil, err
	}
	k.nonce = nonce

	return k, nil
}
