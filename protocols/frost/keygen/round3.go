package keygen

import (
	"github.com/mr-shifu/mpc-lib/core/hash"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/rid"
)

type broadcast3 struct {
	ChainKey     rid.RID
	Decommitment hash.Decommitment
}

type message3 struct {
	VSSShare curve.Scalar
}

// RoundNumber implements round.Content.
func (broadcast3) RoundNumber() round.Number { return 3 }

// RoundNumber implements round.Content.
func (message3) RoundNumber() round.Number { return 3 }