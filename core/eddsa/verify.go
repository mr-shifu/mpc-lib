package eddsa

import (
	"crypto/ed25519"

	"filippo.io/edwards25519"
)

type Signature struct {
	R *edwards25519.Point
	Z *edwards25519.Scalar
}

func Verify(public *edwards25519.Point, sig Signature, msg []byte) bool {
	signature := make([]byte, 64)
	copy(signature[:32], sig.R.Bytes())
	copy(signature[32:], sig.Z.Bytes())

	return ed25519.Verify(public.Bytes(), msg, signature)
}
