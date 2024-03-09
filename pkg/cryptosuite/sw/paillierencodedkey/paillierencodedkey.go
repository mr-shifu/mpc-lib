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
	ErrKeyNotFound = errors.New("key not found")
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

func NewPaillierEncodedkey(secret curve.Scalar, encoded *paillier.Ciphertext, nonce *saferith.Nat) pek.PaillierEncodedKey {
	return &PaillierEncodedKey{
		group:   secret.Curve(),
		secret:  secret,
		encoded: encoded,
		nonce:   nonce,
	}
}

func (k *PaillierEncodedKey) Bytes() ([]byte, error) {
	group := k.group.Name()
	sk_bytes, err := k.secret.MarshalBinary()
	if err != nil {
		return nil, err
	}
	enc_bytes, err := k.encoded.MarshalBinary()
	if err != nil {
		return nil, err
	}
	nonce_bytes, err := k.nonce.MarshalBinary()
	if err != nil {
		return nil, err
	}
	raw := rawPaillierEncodedKey{
		Group:   group,
		Secret:  sk_bytes,
		Encoded: enc_bytes,
		Nonce:   nonce_bytes,
	}
	return cbor.Marshal(raw)
}

func (k *PaillierEncodedKey) Secret() curve.Scalar {
	return k.secret
}

func (k *PaillierEncodedKey) Encoded() *paillier.Ciphertext {
	return k.encoded
}

func (k *PaillierEncodedKey) Nonce() *saferith.Nat {
	return k.nonce
}

func fromBytes(data []byte) (*PaillierEncodedKey, error) {
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
	sk := group.NewScalar()
	err = sk.UnmarshalBinary(raw.Secret)
	if err != nil {
		return nil, err
	}
	enc := &paillier.Ciphertext{}
	err = enc.UnmarshalBinary(raw.Encoded)
	if err != nil {
		return nil, err
	}
	nonce := new(saferith.Nat)
	err = nonce.UnmarshalBinary(raw.Nonce)
	if err != nil {
		return nil, err
	}
	return &PaillierEncodedKey{
		group:   group,
		secret:  sk,
		encoded: enc,
		nonce:   nonce,
	}, nil
}
