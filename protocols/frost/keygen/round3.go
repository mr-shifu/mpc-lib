package keygen

import (
	"github.com/mr-shifu/mpc-lib/core/hash"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/rid"
)

type broadcast3 struct {
	ChainKey     rid.RID
	Decommitment hash.Decommitment
}

// RoundNumber implements round.Content.
func (broadcast3) RoundNumber() round.Number { return 3 }
