package result

import (
	"errors"
	"sync"

	"github.com/google/uuid"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/result"
)

type InMemoryEddsaSignature struct {
	lock       sync.RWMutex
	signatures map[string]*EddsaSignature
	kr         keyopts.KeyOpts
}

func NewInMemoryEddsaSignature(kr keyopts.KeyOpts) *InMemoryEddsaSignature {
	return &InMemoryEddsaSignature{
		signatures: make(map[string]*EddsaSignature),
		kr:         kr,
	}
}

func (s *InMemoryEddsaSignature) Import(sig result.EddsaSignature, opts keyopts.Options) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	id := uuid.New().String()

	signature, ok := sig.(*EddsaSignature)
	if !ok {
		return errors.New("invalid signature type")
	}
	s.signatures[id] = signature

	return s.kr.Import(id, opts)
}

func (s *InMemoryEddsaSignature) Get(opts keyopts.Options) (result.EddsaSignature, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	kd, err := s.kr.Get(opts)
	if err != nil {
		return nil, err
	}
	if kd.SKI == "" {
		return nil, errors.New("key not found")
	}

	sig, ok := s.signatures[kd.SKI]
	if !ok {
		return nil, errors.New("signature not found")
	}

	return sig, nil
}
