package result

import (
	"sync"

	"github.com/google/uuid"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
)

type SigmaStore struct {
	lock   sync.RWMutex
	sigmas keystore.Keystore
}

func NewSigmaStore(s keystore.Keystore) *SigmaStore {
	return &SigmaStore{
		sigmas: s,
	}
}

func (s *SigmaStore) ImportSigma(sigma curve.Scalar, opts keyopts.Options) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	sb, err := sigma.MarshalBinary()
	if err != nil {
		return err
	}
	sigmaID := uuid.New().String()
	if err := s.sigmas.Import(sigmaID, sb, opts); err != nil {
		return err
	}

	return nil
}

func (s *SigmaStore) GetSigma(opts keyopts.Options) (curve.Scalar, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	sb, err := s.sigmas.Get(opts)
	if err != nil {
		return nil, err
	}

	g := curve.Secp256k1{}
	sigma := g.NewScalar()
	if err := sigma.UnmarshalBinary(sb); err != nil {
		return nil, err
	}

	return sigma, nil
}
