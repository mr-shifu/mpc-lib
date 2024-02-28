package hash

import (
	"io"

	core_hash "github.com/mr-shifu/mpc-lib/core/hash"
)

type Hash interface {
	Digest() io.Reader
	Sum() []byte
	WriteAny(...interface{}) error
	Clone() Hash
}

type HashManager interface {
	NewHasher(keyID string, data ...core_hash.WriterToWithDomain) Hash
	RestoreHasher(keyID string) (Hash, error)
}
