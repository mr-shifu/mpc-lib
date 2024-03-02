package vss

import (
	"encoding/hex"
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
		shares map[string]map[string]*cs_vss.VSSShare
	}

	InMemoryLinkedVSSShareStore struct {
		ski   []byte
		store *InMemoryVSSShareStore
	}
)

func NewInMemoryVSSShareStore() *InMemoryVSSShareStore {
	return &InMemoryVSSShareStore{
		shares: make(map[string]map[string]*cs_vss.VSSShare),
	}
}

func (s *InMemoryVSSShareStore) Get(ski []byte, index curve.Scalar) (*cs_vss.VSSShare, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	kid := hex.EncodeToString(ski)

	index_bytes, err := index.MarshalBinary()
	if err != nil {
		return nil, err
	}

	if shares, ok := s.shares[kid]; ok {
		if share, ok := shares[string(index_bytes)]; ok {
			return share, nil
		}
	}

	return nil, ErrShareNotFound
}

func (s *InMemoryVSSShareStore) Import(ski []byte, share *cs_vss.VSSShare) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	kid := hex.EncodeToString(ski)

	index_bytes, err := share.Index.MarshalBinary()
	if err != nil {
		return err
	}

	if _, ok := s.shares[kid]; !ok {
		s.shares[kid] = make(map[string]*cs_vss.VSSShare)
	}
	s.shares[kid][string(index_bytes)] = share

	return nil
}

func (s *InMemoryVSSShareStore) WithSKI(ski []byte) (cs_vss.LinkedVSSShareStore, error) {
	return &InMemoryLinkedVSSShareStore{
		ski:   ski,
		store: s,
	}, nil
}

func (s *InMemoryLinkedVSSShareStore) Get(index curve.Scalar) (*cs_vss.VSSShare, error) {
	return s.store.Get(s.ski, index)
}

func (s *InMemoryLinkedVSSShareStore) Import(share *cs_vss.VSSShare) error {
	return s.store.Import(s.ski, share)
}
