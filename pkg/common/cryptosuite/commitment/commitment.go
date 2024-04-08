package commitment

import "github.com/mr-shifu/mpc-lib/pkg/common/keyopts"

type Commitment interface {
	Bytes() ([]byte, error)

	Commitment() []byte

	Decommitment() []byte
}

type CommitmentManager interface {
	NewCommitment(cmt []byte, dcm []byte) Commitment

	Import(cmt Commitment, opts keyopts.Options) error

	ImportCommitment(cmt []byte, opts keyopts.Options) error

	ImportDecommitment(dcmt []byte, opts keyopts.Options) error

	Get(opts keyopts.Options) (Commitment, error)
}
