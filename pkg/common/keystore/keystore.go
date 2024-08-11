package keystore

import "github.com/mr-shifu/mpc-lib/pkg/common/keyopts"

type Keystore interface {
	Import(keyID string, key []byte, opts keyopts.Options) error
	Update(key []byte, opts keyopts.Options) error
	Get(opts keyopts.Options) ([]byte, error)
	Delete(opts keyopts.Options) error
	DeleteAll(opts keyopts.Options) error
	KeyAccessor(ski string, opts keyopts.Options) KeyAccessor
}

type KeyAccessor interface {
	Import(key []byte) error
	Get() ([]byte, error)
	Delete() error
}
