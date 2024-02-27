package hash

import (
	"io"

	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
)

type Hash interface {
	Digest() io.Reader
	Sum() []byte
	WriteAny(...interface{}) error
	Clone() Hash
	Fork(...interface{}) Hash
}

type HashManager interface {
	NewHasher(keyID string, data ...interface{}) Hash
	RestoreHasher(keyID, store keystore.KeyLinkedStore) (Hash, error)
}
