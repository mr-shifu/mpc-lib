package keyopts

import (
	"errors"

	com_keyopts "github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
)

type Options map[string]interface{}

var _ com_keyopts.Options = Options{}

func NewOptions() Options {
	return Options{}
}

func (opts Options) Set(kVs ...interface{}) (com_keyopts.Options, error) {
	if len(kVs)%2 != 0 {
		return nil, errors.New("keyrepository: invalid options")
	}

	for i := 0; i < len(kVs); i += 2 {
		key := kVs[i].(string)
		val := kVs[i+1]
		opts[key] = val
	}

	return opts, nil
}

func (opts Options) Get(key string) (interface{}, bool) {
	val, ok := opts[key]
	return val, ok
}
