package result

import (
	"errors"
	"sync"

	"github.com/google/uuid"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
)

type InMemoryEddsaSignature struct {
	lock       sync.RWMutex
	signatures map[string]*EddsaSignature
	kr         keyopts.KeyOpts
}

func NewInMemoryEddsaSignature() *InMemoryEddsaSignature {
	return &InMemoryEddsaSignature{
		signatures: make(map[string]*EddsaSignature),
	}
}

func (s *InMemoryEddsaSignature) Import(sig *EddsaSignature, opts keyopts.Options) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	id := uuid.New().String()

	s.signatures[id] = sig

	return s.kr.Import(id, opts)
}

func (s *InMemoryEddsaSignature) Get(opts keyopts.Options) (*EddsaSignature, error) {
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
