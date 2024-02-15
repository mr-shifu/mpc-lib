package round

import (
	"encoding/json"
	"errors"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/pool"
	"github.com/mr-shifu/mpc-lib/protocols/cmp/config"
)

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

type OutputSerialized struct {
	Helper []byte
	Result []byte
}

func NewEmptyKeyResult(g curve.Curve, pl *pool.Pool) *Output {
	return &Output{
		Helper: NewEmptyHelper(g, pl),
		Result: config.NewEmptyConfig(g),
	}
}

func (output *Output) Serialize() (ser []byte, err error) {
	var os OutputSerialized
	os.Helper, err = output.Helper.Serialize()
	if err != nil {
		return nil, err
	}

	switch output.Result.(type) {
	case *config.Config:
		os.Result, err = output.Result.(*config.Config).Serialize()
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unknown type")
	}

	return json.Marshal(os)
}

func (output *Output) Deserialize(data []byte) error {
	var os OutputSerialized
	if err := json.Unmarshal(data, &os); err != nil {
		return err
	}

	if err := output.Helper.Deserialize(os.Helper); err != nil {
		return err
	}

	switch output.Result.(type) {
	case *config.Config:
		if err := output.Result.(*config.Config).Deserialize(os.Result); err != nil {
			return ErrNilFields
		}
	default:
		return errors.New("unknown type")
	}

	return nil
}
