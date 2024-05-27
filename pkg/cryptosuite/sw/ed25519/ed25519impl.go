package ed25519

import (
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"io"

	ed "filippo.io/edwards25519"
	"github.com/pkg/errors"
)

const (
	// PublicKeySize is the size, in bytes, of public keys as used in this package.
	PublicKeySize = 32
	// PrivateKeySize is the size, in bytes, of private keys as used in this package.
	PrivateKeySize = 64
	// SignatureSize is the size, in bytes, of signatures generated and verified by this package.
	SignatureSize = 64
	// SeedSize is the size, in bytes, of private key seeds. These are the private key representations used by RFC 8032.
	SeedSize = 32
)

// Ed25519Impl contains Ed25519 Private and Public Key and implements the Ed25519 interface.
type Ed25519Impl struct {
	s *ed.Scalar
	a *ed.Point
}

// GenerateKey creates a new Ed25519 key pair.
func GenerateKey() (Ed25519, error) {
	rand := cryptorand.Reader

	seed := make([]byte, SeedSize)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, errors.WithMessage(err, "ed25519: failed to read random seed")
	}

	h := sha512.Sum512(seed)
	s, err := ed.NewScalar().SetBytesWithClamping(h[:32])
	if err != nil {
		return nil, errors.WithMessage(err, "ed25519: internal error: setting scalar failed")
	}
	A := (&ed.Point{}).ScalarBaseMult(s)

	k := &Ed25519Impl{
		s: s,
		a: A,
	}

	return k, nil
}

// FromPrivateKey creates a new Ed25519 key from a private key either in bytes or Ed25519 Scalar.
func FromPrivateKey(prv any) (Ed25519, error) {
	switch st := prv.(type) {
	case []byte:
		if len(st) != PrivateKeySize {
			return nil, errors.New("ed25519: bad private key length")
		}

		s, err := ed.NewScalar().SetBytesWithClamping(st[:32])
		if err != nil {
			return nil, errors.WithMessage(err, "ed25519: internal error: setting scalar failed")
		}

		A := (&ed.Point{}).ScalarBaseMult(s)

		return &Ed25519Impl{
			s: s,
			a: A,
		}, nil
	case *ed.Scalar:
		A := (&ed.Point{}).ScalarBaseMult(st)

		return &Ed25519Impl{
			s: st,
			a: A,
		}, nil
	default:
		return nil, errors.New("ed25519: invalid private key type")
	}
}

// FromPublisKey creates a new Ed25519 key from a public key either in bytes or Ed25519 Point.
func FromPublisKey(pub any) (Ed25519, error) {
	switch st := pub.(type) {
	case []byte:
		if len(st) != PublicKeySize {
			return nil, errors.New("ed25519: bad public key length")
		}

		A := &ed.Point{}
		if _, err := A.SetBytes(st); err != nil {
			return nil, errors.WithMessage(err, "ed25519: internal error: setting point failed")
		}

		return &Ed25519Impl{
			s: nil,
			a: A,
		}, nil
	case *ed.Point:
		return &Ed25519Impl{
			s: nil,
			a: st,
		}, nil
	default:
		return nil, errors.New("ed25519: invalid public key type")
	}
}

// Bytes returns the byte representation of the key.
// if key is Private it returns 64-byte key containing 32-byte private key and 32-byte public key
// if key is Public it returns 32-byte public key
func (k *Ed25519Impl) Bytes() ([]byte, error) {
	if k.s != nil {
		raw := make([]byte, PrivateKeySize)
		copy(raw[:32], k.s.Bytes())
		copy(raw[32:], k.a.Bytes())
		return raw, nil
	} else if k.a != nil {
		return k.a.Bytes(), nil
	}
	return nil, nil
}

// SKI returns the serialized key identifier; SKI is the sha256 hash of public key.
func (k *Ed25519Impl) SKI() []byte {
	raw := k.a.Bytes()
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// Private returns true if the key is private.
func (k *Ed25519Impl) Private() bool {
	return k.s != nil
}

// PublicKey returns the corresponding public key part of ECDSA Key.
func (k *Ed25519Impl) PublicKey() Ed25519 {
	return &Ed25519Impl{
		s: nil,
		a: k.a,
	}
}

// FromBytes creates a new Ed25519 key from a byte representation.
func (k *Ed25519Impl) FromBytes(data []byte) error {
	if len(data) != PrivateKeySize && len(data) != PublicKeySize {
		return errors.New("ed25519: bad key length")
	}

	if len(data) == PrivateKeySize {
		sb := data[:32]
		pb := data[32:]

		s, err := ed.NewScalar().SetBytesWithClamping(sb)
		if err != nil {
			return errors.WithMessage(err, "ed25519: internal error: setting scalar failed")
		}

		A := &ed.Point{}
		if _, err := A.SetBytes(pb); err != nil {
			return errors.WithMessage(err, "ed25519: internal error: setting point failed")
		}

		if A.Equal((&ed.Point{}).ScalarBaseMult(s)) != 1 {
			return errors.New("ed25519: public key doesn't match private key")
		}

		k = &Ed25519Impl{s, A}

		return nil
	} else {
		A := &ed.Point{}
		if _, err := A.SetBytes(data); err != nil {
			return errors.WithMessage(err, "ed25519: internal error: setting point failed")
		}

		k = &Ed25519Impl{nil, A}

		return nil
	}
}
