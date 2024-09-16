package ecdsa

import (
	"errors"
	"sync"

	"github.com/google/uuid"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/result"
)

type InMemoryEcdsaSignature struct {
	lock       sync.RWMutex
	signatures map[string]*EcdsaSignature
	kr         keyopts.KeyOpts
}

var _ result.EcdsaSignatureStore = (*InMemoryEcdsaSignature)(nil)

func NewInMemoryEcdsaSignature(kr keyopts.KeyOpts) *InMemoryEcdsaSignature {
	return &InMemoryEcdsaSignature{
		signatures: make(map[string]*EcdsaSignature),
		kr:         kr,
	}
}

func (s *InMemoryEcdsaSignature) Import(sig result.EcdsaSignature, opts keyopts.Options) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	id := uuid.New().String()

	signature, ok := sig.(*EcdsaSignature)
	if !ok {
		return errors.New("invalid signature type")
	}
	s.signatures[id] = signature

	return s.kr.Import(id, opts)
}

func (s *InMemoryEcdsaSignature) Get(opts keyopts.Options) (result.EcdsaSignature, error) {
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
