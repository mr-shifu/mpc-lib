package commitment

import (
	"github.com/mr-shifu/mpc-lib/core/party"
	"github.com/mr-shifu/mpc-lib/pkg/common/commitstore"
)

type CommitmentManager interface {
	Import(keyID string, partyID party.ID, commitment *commitstore.Commitment) error
	Get(keyID string, partyID party.ID) (*commitstore.Commitment, error)
}
