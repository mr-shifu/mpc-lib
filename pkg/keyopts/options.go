package keyopts

import "errors"

type Options map[string]interface{}

func (opts Options) Set(kVs ...interface{}) error {
	if len(kVs)%2 != 0 {
		return errors.New("keyrepository: invalid options")
	}

	for i := 0; i < len(kVs); i += 2 {
		key := kVs[i].(string)
		val := kVs[i+1]
		opts[key] = val
	}

	return nil
}

func (opts Options) Get(key string) (interface{}, bool) {
	val, ok := opts[key]
	return val, ok
}
