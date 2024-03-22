package result

import (
	"sync"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
)

type Signature struct {
	r     curve.Point
	sigma curve.Scalar
}

type SignStore struct {
	lock       sync.RWMutex
	signatures map[string]*Signature
}

func NewSignStore() *SignStore {
	return &SignStore{
		signatures: make(map[string]*Signature),
	}
}
func (s *SignStore) ImportSignR(signID string, r curve.Point) {
	s.lock.Lock()
	defer s.lock.Unlock()

	signature, ok := s.signatures[signID]
	if !ok {
		s.signatures[signID] = &Signature{
			r: r,
		}
		return
	}
	signature.r = r
}
func (s *SignStore) SignR(signID string) curve.Point {
	s.lock.Lock()
	defer s.lock.Unlock()
	
	signature, ok := s.signatures[signID]
	if !ok {
		return nil
	}
	return signature.r
}
func (s *SignStore) ImportSignSigma(signID string, sigma curve.Scalar) {
	s.lock.Lock()
	defer s.lock.Unlock()
	
	signature, ok := s.signatures[signID]
	if !ok {
		s.signatures[signID] = &Signature{
			sigma: sigma,
		}
		return
	}
	signature.sigma = sigma
}
func (s *SignStore) SignSigma(signID string) curve.Scalar {
	s.lock.Lock()
	defer s.lock.Unlock()
	
	signature, ok := s.signatures[signID]
	if !ok {
		return nil
	}
	return signature.sigma
}
