package mta

import (
	"github.com/cronokirby/saferith"
	comm_mta "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/mta"
)

type MtAManager interface {
	GetKey(keyID string, partyID string) (comm_mta.MtA, error)
	ImportKey(keyID string, partyID string, k comm_mta.MtA) (comm_mta.MtA, error)
	SetAlpha(keyID string, partyID string, alpha *saferith.Int) error
	SetBeta(keyID string, partyID string, beta *saferith.Int) error
}
