package paillierencodedkey

import (
	"errors"

	"github.com/cronokirby/saferith"
	"github.com/fxamacker/cbor/v2"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/paillier"
	pek "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/paillierencodedkey"
)

var (
	ErrKeyNotFound = errors.New("paillierencodedkey: key not found")
)

type PaillierEncodedKey struct {
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

func NewPaillierEncodedkey(secret curve.Scalar, encoded *paillier.Ciphertext, nonce *saferith.Nat, curve curve.Curve) pek.PaillierEncodedKey {
	return &PaillierEncodedKey{
		group:   curve,
		secret:  secret,
		encoded: encoded,
		nonce:   nonce,
	}
}

func (k PaillierEncodedKey) Bytes() ([]byte, error) {
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

func (k PaillierEncodedKey) Secret() curve.Scalar {
	return k.secret
}

func (k PaillierEncodedKey) Encoded() *paillier.Ciphertext {
	return k.encoded
}

func (k PaillierEncodedKey) Nonce() *saferith.Nat {
	return k.nonce
}

func fromBytes(data []byte) (PaillierEncodedKey, error) {
	var raw rawPaillierEncodedKey
	err := cbor.Unmarshal(data, &raw)
	if err != nil {
		return PaillierEncodedKey{}, err
	}

	var group curve.Curve
	switch raw.Group {
	case "secp256k1":
		group = curve.Secp256k1{}
	}

	k := &PaillierEncodedKey{
		group: group,
	}

	if raw.Secret != nil {
		sk := group.NewScalar()
		err = sk.UnmarshalBinary(raw.Secret)
		if err != nil {
			return PaillierEncodedKey{}, err
		}
		k.secret = sk
	}

	enc := &paillier.Ciphertext{}
	err = enc.UnmarshalBinary(raw.Encoded)
	if err != nil {
		return PaillierEncodedKey{}, err
	}
	k.encoded = enc

	nonce := new(saferith.Nat)
	err = nonce.UnmarshalBinary(raw.Nonce)
	if err != nil {
		return PaillierEncodedKey{}, err
	}
	k.nonce = nonce

	return *k, nil
}
