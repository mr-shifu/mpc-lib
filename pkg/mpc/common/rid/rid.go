package rid

import (
	comm_rid "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/rid"
)

type RIDKeyManager interface {
	GenerateKey(keyID string, partyID string) (comm_rid.RID, error)
	ImportKey(keyID string, partyID string, data []byte) (comm_rid.RID, error)
	GetKey(keyID string, partyID string) (comm_rid.RID, error)
}