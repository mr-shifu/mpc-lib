package keyopts

import "github.com/mr-shifu/mpc-lib/pkg/common/keyopts"

type InMemoryKeyOptsFactory struct {}

// NewKeyOpts creates a new KeyOpts instance for the given Opts configuration
func (f *InMemoryKeyOptsFactory) NewKeyOpts(cfg interface{}) keyopts.KeyOpts {
	return NewInMemoryKeyOpts()
}