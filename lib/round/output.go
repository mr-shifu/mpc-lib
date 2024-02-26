package round

// Output is an empty round containing the output of the protocol.
type Output struct {
	*Helper
	Result interface{}
}

func (Output) VerifyMessage(Message) error                  { return nil }
func (Output) StoreMessage(Message) error                   { return nil }
func (r *Output) Finalize(chan<- *Message) (Session, error) { return r, nil }
func (r *Output) CanFinalize() bool                         { return false }
func (Output) MessageContent() Content                      { return nil }
func (Output) Number() Number                               { return 0 }
func (r *Output) Equal(other Round) bool                    { return true }
