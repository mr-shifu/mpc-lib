package sign

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/lib/round"
)

type broadcast3 struct {
	round.NormalBroadcastContent
	// Z_i is the response scalar computed by the sender of this message.
	Z curve.Scalar
}

// RoundNumber implements round.Content.
func (broadcast3) RoundNumber() round.Number { return 3 }
