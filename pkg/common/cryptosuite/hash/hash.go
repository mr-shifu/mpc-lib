package hash

import (
	"io"

	core_hash "github.com/mr-shifu/mpc-lib/core/hash"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
)

type Hash interface {
	Digest() io.Reader
	Sum() []byte
	WriteAny(...interface{}) error
	Clone() Hash
	Commit(data ...interface{}) (core_hash.Commitment, core_hash.Decommitment, error)
	Decommit(c core_hash.Commitment, d core_hash.Decommitment, data ...interface{}) bool
}

type HashManager interface {
	NewHasher(keyID string, opts keyopts.Options, data ...core_hash.WriterToWithDomain) Hash
	RestoreHasher(keyID string, opts keyopts.Options) (Hash, error)
}
