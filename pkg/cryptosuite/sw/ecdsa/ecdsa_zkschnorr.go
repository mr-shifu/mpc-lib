package ecdsa

import (
	"crypto/rand"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	"github.com/pkg/errors"
)

const (
	SchnorrProofSize    = 97
	SchnorrProofSizeNoC = 65
)

type Commitment struct {
	c curve.Scalar
	C curve.Point
}

func NewCommitment(c curve.Scalar, C curve.Point) *Commitment {
	return &Commitment{c, C}
}

func (c *Commitment) Public() curve.Point {
	return c.C
}

func (c *Commitment) Bytes() ([]byte, error) {
	if c.C == nil {
		return nil, errors.New("ecdsa_zksch: commitment is not initialized")
	}
	if c.c == nil {
		Cb, _ := c.C.MarshalBinary()
		b := make([]byte, 33)
		copy(b[:33], Cb)
		return b, nil
	} else {
		Cb, _ := c.C.MarshalBinary()
		cb, _ := c.c.MarshalBinary()
		b := make([]byte, 65)
		copy(b[:33], Cb)
		copy(b[33:], cb)
		return b, nil
	}
}

func (c *Commitment) FromBytes(data []byte) error {
	if len(data) != 33 && len(data) != 65 {
		return errors.New("ecdsa_zksch: bad commitment length")
	}

	group := curve.Secp256k1{}

	C := group.NewPoint()
	if err := C.UnmarshalBinary(data[:33]); err != nil {
		return errors.WithMessage(err, "ecdsa_zksch: internal error: setting point failed")
	}
	c.C = C

	if len(data) == 65 {
		cc := group.NewScalar()
		if err := cc.UnmarshalBinary(data[33:]); err != nil {
			return errors.WithMessage(err, "ecdsa_zksch: internal error: setting scalar failed")
		}
		c.c = cc
	}

	return nil
}

type Response struct {
	Z curve.Scalar
}

func NewResponse(Z curve.Scalar) *Response {
	return &Response{Z}
}

func (r *Response) Bytes() ([]byte, error) {
	if r.Z == nil {
		return nil, errors.New("ecdsa_zksch: response is not initialized")
	}

	Zb, _ := r.Z.MarshalBinary()
	return Zb, nil
}

func (r *Response) FromBytes(data []byte) error {
	if len(data) != 32 {
		return errors.New("ecdsa_zksch: bad response length")
	}

	group := curve.Secp256k1{}

	Z := group.NewScalar()
	if err := Z.UnmarshalBinary(data); err != nil {
		return errors.WithMessage(err, "ecdsa_zksch: internal error: setting scalar failed")
	}
	r.Z = Z

	return nil
}

type Proof struct {
	cmt *Commitment
	rsp *Response
}

type proof struct {
	Cmt []byte
	Rsp []byte
}

func NewProof(cmt *Commitment, rsp *Response) *Proof {
	return &Proof{cmt, rsp}
}

func (p *Proof) SetCommitment(c *Commitment) {
	p.cmt = c
}

func (p *Proof) SetResponse(r *Response) {
	p.rsp = r
}

func (p *Proof) Bytes() ([]byte, error) {
	pf := new(proof)

	if p.cmt != nil {
		pf.Cmt, _ = p.cmt.Bytes()
	}
	if p.rsp != nil {
		pf.Rsp, _ = p.rsp.Bytes()
	}

	return cbor.Marshal(pf)
}

func (p *Proof) FromBytes(data []byte) error {
	var pf proof
	if err := cbor.Unmarshal(data, &pf); err != nil {
		return errors.WithMessage(err, "ecdsa_zksch: failed to unmarshal proof")
	}

	if len(pf.Cmt) != 0 {
		cmt := new(Commitment)
		if err := cmt.FromBytes(pf.Cmt); err != nil {
			return errors.WithMessage(err, "ecdsa_zksch: failed to unmarshal commitment")
		}
		p.cmt = cmt
	}

	if len(pf.Rsp) != 0 {
		rsp := new(Response)
		if err := rsp.FromBytes(pf.Rsp); err != nil {
			return errors.WithMessage(err, "ecdsa_zksch: failed to unmarshal response")
		}
		p.rsp = rsp
	}

	return nil
}

func (p *Proof) GenerateCommitment(h hash.Hash) (*Commitment, error) {
	cmt, err := newSchnorrCommitment(h)
	if err != nil {
		return nil, errors.WithMessage(err, "ecdsa_zksch: failed to create commitment")
	}
	p.cmt = cmt
	return cmt, nil
}

func (p *Proof) GenerateResponse(h hash.Hash, private curve.Scalar) (*Response, error) {
	rsp, err := newSchnorrResponse(h, private, p.cmt)
	if err != nil {
		return nil, errors.WithMessage(err, "ecdsa_zksch: failed to create response")
	}
	p.rsp = rsp
	return rsp, nil
}

func (p *Proof) VerifySchnorrProof(h hash.Hash, proof *Proof, public curve.Point) (bool, error) {
	return verifySchnorrProof(h, proof, public)
}

func (p *Proof) Commitment() *Commitment {
	return &Commitment{nil, p.cmt.C}
}

func (p *Proof) Response() *Response {
	return &Response{p.rsp.Z}
}

func newSchnorrCommitment(h hash.Hash) (*Commitment, error) {
	group := curve.Secp256k1{}

	rand := rand.Reader

	a := sample.Scalar(rand, group)

	return &Commitment{a, a.ActOnBase()}, nil
}

func newSchnorrResponse(h hash.Hash, private curve.Scalar, commitment *Commitment) (*Response, error) {
	public := private.ActOnBase()
	challenge, err := newSchnorrChallenge(h.Clone(), commitment.C, public)
	if err != nil {
		return nil, errors.WithMessage(err, "ecdsa_zksch: failed to create challenge")
	}

	p := private.Mul(challenge)
	p = p.Add(commitment.c)

	return &Response{p}, nil
}

func newSchnorrChallenge(h hash.Hash, commitment curve.Point, public curve.Point) (curve.Scalar, error) {
	group := commitment.Curve()
	gen := group.NewBasePoint()

	cmtBytes, err := commitment.MarshalBinary()
	if err != nil {
		return nil, err
	}
	publicBytes, err := public.MarshalBinary()
	if err != nil {
		return nil, err
	}

	if err := h.WriteAny(cmtBytes, publicBytes, gen); err != nil {
		return nil, err
	}

	e := sample.Scalar(h.Digest(), group)

	return e, nil
}

func newSchnorrProof(h hash.Hash, private curve.Scalar, public curve.Point) (*Proof, error) {
	cmt, err := newSchnorrCommitment(h.Clone())
	if err != nil {
		return nil, errors.WithMessage(err, "ecdsa_zksch: failed to create commitment")
	}

	rsp, err := newSchnorrResponse(h.Clone(), private, cmt)
	if err != nil {
		return nil, errors.WithMessage(err, "ecdsa_zksch: failed to create response")
	}

	return &Proof{
		cmt: cmt,
		rsp: rsp,
	}, nil
}

func verifySchnorrProof(h hash.Hash, proof *Proof, public curve.Point) (bool, error) {
	challenge, err := newSchnorrChallenge(h.Clone(), proof.Commitment().C, public)
	fmt.Printf("verify challenge: %v\n", challenge)
	if err != nil {
		return false, errors.WithMessage(err, "ecdsa_zksch: failed to create challenge")
	}

	lhs := proof.Response().Z.ActOnBase()

	rhs := challenge.Act(public)
	rhs = rhs.Add(proof.cmt.C)

	return lhs.Equal(rhs), nil
}
