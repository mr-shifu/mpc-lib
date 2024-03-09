package result

import (
	"sync"

	"github.com/google/uuid"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyrepository"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
)

type SigmaStore struct {
	lock   sync.RWMutex
	sigmas keystore.Keystore
	repo   keyrepository.KeyRepository
}

func NewSigmaStore(s keystore.Keystore, r keyrepository.KeyRepository) *SigmaStore {
	return &SigmaStore{
		sigmas: s,
		repo:   r,
	}
}

func (s *SigmaStore) ImportSigma(signID, partyID string, sigma curve.Scalar) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	sb, err := sigma.MarshalBinary()
	if err != nil {
		return err
	}
	sigmaID := uuid.New().String()
	if err := s.sigmas.Import(sigmaID, sb); err != nil {
		return err
	}

	s.repo.Import(signID, keyrepository.KeyData{
		PartyID: partyID,
		SKI:     []byte(sigmaID),
	})

	return nil
}

func (s *SigmaStore) GetSigma(signID, partyID string) (curve.Scalar, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	keys, err := s.repo.GetAll(signID)
	if err != nil {
		return nil, err
	}

	k, ok := keys[partyID]
	if !ok {
		return nil, nil
	}

	sb, err := s.sigmas.Get(string(k.SKI))
	if err != nil {
		return nil, err
	}

	var sigma curve.Scalar
	if err := sigma.UnmarshalBinary(sb); err != nil {
		return nil, err
	}

	return sigma, nil
}
