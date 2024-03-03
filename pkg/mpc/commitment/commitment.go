package commitment

import (
	"errors"

	"github.com/google/uuid"
	"github.com/mr-shifu/mpc-lib/core/party"
	"github.com/mr-shifu/mpc-lib/pkg/common/commitstore"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/commitment"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyrepository"
)

type CommitmentManager struct {
	commitstore commitstore.CommitStore
	kr          keyrepository.KeyRepository
}

func NewCommitmentManager(commitstore commitstore.CommitStore, kr keyrepository.KeyRepository) commitment.CommitmentManager {
	return &CommitmentManager{commitstore: commitstore, kr: kr}
}

func (mgr *CommitmentManager) Get(keyID string, partyID party.ID) (*commitstore.Commitment, error) {
	commits, err := mgr.kr.GetAll(keyID)
	if err != nil {
		return nil, err
	}

	commit, ok := commits[string(partyID)]
	if !ok {
		return nil, errors.New("key not found")
	}

	return mgr.commitstore.Get(string(commit.SKI))
}

func (mgr *CommitmentManager) Import(keyID string, partyID party.ID, commitment *commitstore.Commitment) error {
	cmtID := uuid.New().String()
	if err := mgr.commitstore.Import(cmtID, commitment); err != nil {
		return err
	}

	return mgr.kr.Import(keyID, keyrepository.KeyData{
		PartyID: string(partyID),
		SKI:     []byte(cmtID),
	})
}
