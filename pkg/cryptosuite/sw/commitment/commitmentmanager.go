package commitment

import (
	"errors"

	"github.com/google/uuid"
	comm_commitment "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/commitment"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
)

type CommitmentManager struct {
	ks keystore.Keystore
}

func NewCommitmentManager(ks keystore.Keystore) *CommitmentManager {
	return &CommitmentManager{
		ks: ks,
	}
}

func (cm *CommitmentManager) NewCommitment(cmt []byte, dcm []byte) comm_commitment.Commitment {
	return &Commitment{
		cmt:  cmt,
		dcmt: dcm,
	}
}

func (cm *CommitmentManager) Import(cmt comm_commitment.Commitment, opts keyopts.Options) error {
	cb, err := cmt.Bytes()
	if err != nil {
		return err
	}

	kid := uuid.New().String()

	err = cm.ks.Import(kid, cb, opts)

	return err
}

func (cm *CommitmentManager) ImportCommitment(cmt []byte, opts keyopts.Options) error {
	cc, err := cm.Get(opts)
	if err != nil {
		return err
	}

	c, ok := cc.(*Commitment)
	if !ok {
		return errors.New("invalid commitment type")
	}
	c.cmt = cmt

	return cm.Import(c, opts)
}

func (cm *CommitmentManager) ImportDecommitment(dcmt []byte, opts keyopts.Options) error {
	cc, err := cm.Get(opts)
	if err != nil {
		return err
	}

	c, ok := cc.(*Commitment)
	if !ok {
		return errors.New("invalid commitment type")
	}
	c.dcmt = dcmt

	return cm.Import(c, opts)
}

func (cm *CommitmentManager) Get(opts keyopts.Options) (comm_commitment.Commitment, error) {
	cb, err := cm.ks.Get(opts)
	if err != nil {
		return nil, err
	}

	cmt, err := fromBytes(cb)
	if err != nil {
		return nil, err
	}

	return cmt, nil
}
