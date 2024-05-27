package ed25519

import (
	cryptorand "crypto/rand"
	"io"

	ed "filippo.io/edwards25519"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
	"github.com/pkg/errors"
)

type Commitment struct {
	c *ed.Scalar
	C *ed.Point
}

type Response struct {
	Z *ed.Scalar
}

type Proof struct {
	cmt *Commitment
	rsp *Response
}

func (p *Proof) Commitment() *Commitment {
	return &Commitment{nil, p.cmt.C}
}
func (p *Proof) Response() *Response {
	return &Response{p.rsp.Z}
}

func (p *Proof) Bytes() []byte {
	pp := &Proof{
		cmt: &Commitment{nil, p.cmt.C},
		rsp: &Response{Z: p.rsp.Z},
	}
	return pp.bytes()
}

func (p *Proof) bytes() []byte {
	if p.cmt.c != nil {
		pb := make([]byte, 96)
		copy(pb[:32], p.cmt.c.Bytes())
		copy(pb[32:64], p.cmt.C.Bytes())
		copy(pb[64:], p.rsp.Z.Bytes())
		return pb
	} else {
		pb := make([]byte, 64)
		copy(pb[:32], p.cmt.C.Bytes())
		copy(pb[32:], p.rsp.Z.Bytes())
		return pb
	}
}

func (p *Proof) fromBytes(data []byte) error {
	if len(data) != 96 && len(data) != 64 {
		return errors.New("ed25519_zksch: bad proof length")
	}

	if len(data) == 96 {
		c, err := ed.NewScalar().SetBytesWithClamping(data[:32])
		if err != nil {
			return errors.WithMessage(err, "ed25519_zksch: internal error: setting scalar failed")
		}

		C, err := (&ed.Point{}).SetBytes(data[32:64])
		if err != nil {
			return errors.WithMessage(err, "ed25519_zksch: internal error: setting point failed")
		}

		if C.Equal((&ed.Point{}).ScalarBaseMult(c)) != 1 {
			return errors.New("ed25519_zksch: commitment does not match")
		}

		Z, err := ed.NewScalar().SetBytesWithClamping(data[64:])
		if err != nil {
			return errors.WithMessage(err, "ed25519_zksch: internal error: setting scalar failed")
		}

		p.cmt = &Commitment{c, C}
		p.rsp = &Response{Z}

		return nil
	} else {
		C, err := (&ed.Point{}).SetBytes(data[32:64])
		if err != nil {
			return errors.WithMessage(err, "ed25519_zksch: internal error: setting point failed")
		}

		Z, err := ed.NewScalar().SetBytesWithClamping(data[64:])
		if err != nil {
			return errors.WithMessage(err, "ed25519_zksch: internal error: setting scalar failed")
		}

		p.cmt = &Commitment{nil, C}
		p.rsp = &Response{Z}

		return nil
	}
}

func (k *Ed25519Impl) NewScnorrProof(h hash.Hash) (*Proof, error) {
	return newSchnorrProof(h, k.s, k.a)
}

func (k *Ed25519Impl) VerifySchnorrProof(h hash.Hash, proof *Proof) (bool, error) {
	return verifySchnorrProof(h, proof, k.a)
}

func newSchnorrCommitment(h hash.Hash) (*Commitment, error) {
	rand := cryptorand.Reader

	seed := make([]byte, SeedSize)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, errors.WithMessage(err, "ed25519_zksch: failed to read random seed")
	}

	if err := h.WriteAny(seed); err != nil {
		return nil, errors.WithMessage(err, "ed25519_zksch: failed to write seed to hash")
	}
	r := h.Sum()
	c, err := ed.NewScalar().SetBytesWithClamping(r[:32])
	if err != nil {
		return nil, errors.WithMessage(err, "ed25519_zksch: internal error: setting scalar failed")
	}
	C := (&ed.Point{}).ScalarBaseMult(c)

	return &Commitment{c, C}, nil
}

func newSchnorrChallenge(h hash.Hash, commitment *ed.Point, public *ed.Point) (*ed.Scalar, error) {
	if err := h.WriteAny(commitment, public); err != nil {
		return nil, errors.WithMessage(err, "ed25519_zksch: failed to write commitment and public key to hash")
	}
	r := h.Sum()
	c, err := ed.NewScalar().SetBytesWithClamping(r[:32])
	if err != nil {
		return nil, errors.WithMessage(err, "ed25519_zksch: internal error: setting scalar failed")
	}
	return c, nil
}

func newSchnorrProof(h hash.Hash, private *ed.Scalar, public *ed.Point) (*Proof, error) {
	cmt, err := newSchnorrCommitment(h)
	if err != nil {
		return nil, errors.WithMessage(err, "ed25519_zksch: failed to create commitment")
	}

	challenge, err := newSchnorrChallenge(h, cmt.C, public)
	if err != nil {
		return nil, errors.WithMessage(err, "ed25519_zksch: failed to create challenge")
	}

	p := &ed.Scalar{}
	p = p.MultiplyAdd(private, challenge, cmt.c)

	return &Proof{
		cmt: cmt,
		rsp: &Response{Z: p},
	}, nil
}

func verifySchnorrProof(h hash.Hash, proof *Proof, public *ed.Point) (bool, error) {
	challenge, err := newSchnorrChallenge(h, proof.Commitment().C, public)
	if err != nil {
		return false, errors.WithMessage(err, "ed25519_zksch: failed to create challenge")
	}

	lhs := (&ed.Point{}).ScalarBaseMult(proof.Response().Z)

	rhs := (&ed.Point{}).ScalarMult(challenge, public)
	rhs = rhs.Add(rhs, proof.cmt.C)

	return lhs.Equal(rhs) == 1, nil
}
