package paillierencodedkey

import (
	"github.com/cronokirby/saferith"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/paillier"
)

type PaillierEncodedKey interface {
	Bytes() ([]byte, error)

	Secret() curve.Scalar

	Encoded() *paillier.Ciphertext

	Nonce() *saferith.Nat
}

type PaillierEncodedKeyManager interface {
	Get(keyID string) (PaillierEncodedKey, error)
	Import(keyID string, key PaillierEncodedKey) (PaillierEncodedKey, error)
}
