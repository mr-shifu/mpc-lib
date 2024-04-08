package keystore

import "github.com/mr-shifu/mpc-lib/pkg/common/keyopts"

type InMemoryKeyAccessor struct {
	opts keyopts.Options
	ski  string
	ks   *InMemoryKeystore
}

func NewInMemoryKeyAccessor(ski string, opts keyopts.Options, ks *InMemoryKeystore) *InMemoryKeyAccessor {
	return &InMemoryKeyAccessor{ski: ski, opts: opts, ks: ks}
}

func (kls *InMemoryKeyAccessor) Import(key []byte) error {
	return kls.ks.Import(kls.ski, key, kls.opts)
}

func (kls *InMemoryKeyAccessor) Get() ([]byte, error) {
	return kls.ks.Get(kls.opts)
}

func (kls *InMemoryKeyAccessor) Delete() error {
	return kls.ks.Delete(kls.opts)
}
