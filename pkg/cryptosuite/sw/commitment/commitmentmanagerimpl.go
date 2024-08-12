package commitment

import (
	"errors"

	"github.com/google/uuid"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
)

type CommitmentManagerImpl struct {
	ks keystore.Keystore
}

func NewCommitmentManagerImpl(ks keystore.Keystore) *CommitmentManagerImpl {
	return &CommitmentManagerImpl{
		ks: ks,
	}
}

func (cm *CommitmentManagerImpl) NewCommitment(cmt []byte, dcm []byte) Commitment {
	return &CommitmentImpl{
		cmt:  cmt,
		dcmt: dcm,
	}
}

func (cm *CommitmentManagerImpl) Import(cmt Commitment, opts keyopts.Options) error {
	cb, err := cmt.Bytes()
	if err != nil {
		return err
	}

	kid := uuid.New().String()

	err = cm.ks.Import(kid, cb, opts)

	return err
}

func (cm *CommitmentManagerImpl) ImportCommitment(cmt []byte, opts keyopts.Options) error {
	cc, err := cm.Get(opts)
	if err != nil {
		return err
	}

	c, ok := cc.(*CommitmentImpl)
	if !ok {
		return errors.New("invalid commitment type")
	}
	c.cmt = cmt

	return cm.Import(c, opts)
}

func (cm *CommitmentManagerImpl) ImportDecommitment(dcmt []byte, opts keyopts.Options) error {
	cc, err := cm.Get(opts)
	if err != nil {
		return err
	}

	c, ok := cc.(*CommitmentImpl)
	if !ok {
		return errors.New("invalid commitment type")
	}
	c.dcmt = dcmt

	return cm.Import(c, opts)
}

func (cm *CommitmentManagerImpl) Get(opts keyopts.Options) (Commitment, error) {
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
