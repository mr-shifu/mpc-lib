package sample

import (
	cryptorand "crypto/rand"
	"crypto/sha512"
	"io"

	ed "filippo.io/edwards25519"
	"github.com/pkg/errors"
)

const (
	SeedSize = 32
)

func Ed25519Scalar(rand io.Reader) (*ed.Scalar, error) {
	if rand == nil {
		rand = cryptorand.Reader
	}

	seed := make([]byte, SeedSize)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, errors.WithMessage(err, "sample_ed25519: failed to read random seed")
	}

	h := sha512.Sum512(seed)
	s, err := ed.NewScalar().SetBytesWithClamping(h[:32])
	if err != nil {
		return nil, errors.WithMessage(err, "sample_ed25519: internal error: setting scalar failed")
	}

	return s, nil
}
