package keystore

import (
	"errors"

	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/common/vault"
)

var (
	ErrKeyNotFound = errors.New("keystore: key not found")
)

type InMemoryKeystore struct {
	v  vault.Vault
	kr keyopts.KeyOpts
}

func NewInMemoryKeystore(v vault.Vault, kr keyopts.KeyOpts) *InMemoryKeystore {
	return &InMemoryKeystore{
		v:  v,
		kr: kr,
	}
}

func (ks *InMemoryKeystore) Import(ski string, key []byte, opts keyopts.Options) error {
	// store key to vault
	if err := ks.v.Import(ski, key); err != nil {
		return err
	}

	// import key metadata to key repository
	if err := ks.kr.Import(ski, opts); err != nil {
		return err
	}

	return nil
}

func (ks *InMemoryKeystore) Update(key []byte, opts keyopts.Options) error {
	kd, err := ks.kr.Get(opts)
	if err != nil {
		return err
	}
	if kd.SKI == "" {
		return ErrKeyNotFound
	}
	return ks.v.Import(kd.SKI, key)
}

func (ks *InMemoryKeystore) Get(opts keyopts.Options) ([]byte, error) {
	kd, err := ks.kr.Get(opts)
	if err != nil {
		return nil, err
	}

	return ks.v.Get(kd.SKI)
}

func (ks *InMemoryKeystore) Delete(opts keyopts.Options) error {
	kd, err := ks.kr.Get(opts)
	if err != nil {
		return err
	}

	if err := ks.v.Delete(kd.SKI); err != nil {
		return err
	}

	if err := ks.kr.Delete(opts); err != nil {
		return err
	}

	return nil
}

func (ks *InMemoryKeystore) DeleteAll(opts keyopts.Options) error {
	keys, err := ks.kr.GetAll(opts)
	if err != nil {
		return err
	}
	for _, key := range keys {
		if err := ks.v.Delete(key.SKI); err != nil {
			return err
		}
	}

	if err := ks.kr.DeleteAll(opts); err != nil {
		return err
	}

	return nil
}

func (ks *InMemoryKeystore) KeyAccessor(ski string, opts keyopts.Options) keystore.KeyAccessor {
	return NewInMemoryKeyAccessor(ski, opts, ks)
}
