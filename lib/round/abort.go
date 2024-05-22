package round

import "github.com/mr-shifu/mpc-lib/core/party"

// Abort is an empty round containing a list of parties who misbehaved.
type Abort struct {
	*Helper
	Culprits []party.ID
	Err      error
}

func (Abort) VerifyMessage(Message) error                  { return nil }
func (Abort) StoreMessage(Message) error                   { return nil }
func (Abort) StoreBroadcastMessage(Message) error          { return nil }
func (r *Abort) Finalize(chan<- *Message) (Session, error) { return r, nil }
func (r *Abort) CanFinalize() bool                         { return false }
func (Abort) MessageContent() Content                      { return nil }
func (Abort) Number() Number                               { return 0 }
func (Abort) Equal(Round) bool                             { return true }
