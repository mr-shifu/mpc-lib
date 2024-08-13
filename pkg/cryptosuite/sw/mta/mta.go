package mta

import (
	"github.com/cronokirby/saferith"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
)

type MtA interface {
	Bytes() ([]byte, error)
	Alpha() *saferith.Int
	Beta() *saferith.Int
	SetAlpha(alpha *saferith.Int)
	SetBeta(beta *saferith.Int)
}

type MtAManager interface {
	Get(opts keyopts.Options) (MtA, error)
	Import(key MtA, opts keyopts.Options) error
	SetAlpha(alpha *saferith.Int, opts keyopts.Options) error
	SetBeta(beta *saferith.Int, opts keyopts.Options) error
}
