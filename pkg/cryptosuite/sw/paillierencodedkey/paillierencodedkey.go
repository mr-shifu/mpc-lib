package paillierencodedkey

import (
	"github.com/cronokirby/saferith"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/paillier"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
)

type PaillierEncodedKey interface {
	Bytes() ([]byte, error)

	Secret() curve.Scalar

	Encoded() *paillier.Ciphertext

	Nonce() *saferith.Nat
}

type PaillierEncodedKeyManager interface {
	Get(opts keyopts.Options) (PaillierEncodedKey, error)
	Import(raw interface{}, opts keyopts.Options) (PaillierEncodedKey, error)
}
