package protocol

import (
	"github.com/mr-shifu/mpc-lib/lib/round"
)

type Processor interface {
	Start(cfg any) StartFunc
	GetRound(ID string) (round.Session, error)
	StoreBroadcastMessage(ID string, msg round.Message) error
	StoreMessage(ID string, msg round.Message) error
	Finalize(out chan<- *round.Message, ID string) (round.Session, error)
	CanFinalize(keyID string) (bool, error)
}
