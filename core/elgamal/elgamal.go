package elgamal

import (
	"crypto/rand"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
)

type (
	PublicKey = curve.Point
	Nonce     = curve.Scalar
)

// Encrypt returns the encryption of `message` as (L=nonce⋅G, M=message⋅G + nonce⋅public), as well as the `nonce`.
func Encrypt(public PublicKey, message curve.Scalar) (*Ciphertext, Nonce) {
	group := public.Curve()
	nonce := sample.Scalar(rand.Reader, group)
	L := nonce.ActOnBase()
	M := message.ActOnBase().Add(nonce.Act(public))
	return &Ciphertext{
		L: L,
		M: M,
	}, nonce
}

func (Ciphertext) Domain() string {
	return "ElGamal Ciphertext"
}
