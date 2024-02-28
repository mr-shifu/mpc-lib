package vss

import (
	"errors"
	"sync"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
	cs_vss "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/vss"

)

var (
	ErrShareAlreadyExists = errors.New("share already exists")
	ErrShareNotFound      = errors.New("share not found")
)

type (
	InMemoryVSSShareStore struct {
		lock   sync.RWMutex
		shares map[string]map[curve.Scalar]curve.Point
	}

	InMemoryLinkedVSSShareStore struct {
		ski   []byte
		store *InMemoryVSSShareStore
	}
)

func NewInMemoryVSSShareStore() *InMemoryVSSShareStore {
	return &InMemoryVSSShareStore{
		shares: make(map[string]map[curve.Scalar]curve.Point),
	}
}

func (s *InMemoryVSSShareStore) Get(ski []byte, index curve.Scalar) (curve.Point, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	if shares, ok := s.shares[string(ski)]; ok {
		if share, ok := shares[index]; ok {
			return share, nil
		}
	}

	return nil, ErrShareNotFound
}

func (s *InMemoryVSSShareStore) Import(ski []byte, index curve.Scalar, share curve.Point) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if _, ok := s.shares[string(ski)]; !ok {
		s.shares[string(ski)] = make(map[curve.Scalar]curve.Point)
		return nil
	}

	return ErrShareAlreadyExists
}

func (s *InMemoryVSSShareStore) WithSKI(ski []byte) (cs_vss.LinkedVSSShareStore, error) {
	return &InMemoryLinkedVSSShareStore{
		ski:   ski,
		store: s,
	}, nil
}

func (s *InMemoryLinkedVSSShareStore) Get(index curve.Scalar) (curve.Point, error) {
	return s.store.Get(s.ski, index)
}

func (s *InMemoryLinkedVSSShareStore) Import(index curve.Scalar, share curve.Point) error {
	return s.store.Import(s.ski, index, share)
}