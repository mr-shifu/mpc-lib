package mta

import "github.com/cronokirby/saferith"

type MtA interface {
	Bytes() ([]byte, error)
	Alpha() *saferith.Int
	Beta() *saferith.Int
	SetAlpha(alpha *saferith.Int)
	SetBeta(beta *saferith.Int)
}

type MtAManager interface {
	Get(keyID string) (MtA, error)
	Import(keyID string, key MtA) error
	SetAlpha(keyID string, alpha *saferith.Int) error
	SetBeta(keyID string, beta *saferith.Int) error
}
