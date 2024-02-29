package zkschnorrstore

import (
	"crypto/rand"
	"errors"

	"github.com/fxamacker/cbor/v2"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
)

var (
	ErrKeyExists   = errors.New("key exists")
	ErrKeyNotFound = errors.New("key not found")
)

type ZKSchnorr struct {
	group curve.Curve
	// random secret
	alpha curve.Scalar
	// commitment
	bigAlpha curve.Point
	// challenge
	c curve.Scalar
	// proof
	z curve.Scalar

	store keystore.KeyLinkedStore
}

type rawZKSchnorr struct {
	Group    string
	Alpha    []byte
	BigAlpha []byte
	C        []byte
	Z        []byte
}

func NewZKSchnorr(zks keystore.KeyLinkedStore) *ZKSchnorr {
	return &ZKSchnorr{
		store: zks,
	}
}

func (zksch *ZKSchnorr) NewCommitment(group curve.Curve) (curve.Point, error) {
	g := group.NewBasePoint()

	alpha := sample.Scalar(rand.Reader, group)
	bigAlpha := alpha.Act(g)

	zksch.alpha = alpha
	zksch.bigAlpha = bigAlpha

	if err := zksch.save(zksch); err != nil {
		return nil, err
	}

	return bigAlpha, nil
}

func (zksch *ZKSchnorr) ImportCommitment(commitment curve.Point, group curve.Curve) error {
	if !isValidCommitment(commitment) {
		return errors.New("invalid commitment")
	}

	sch := &ZKSchnorr{
		group:    group,
		bigAlpha: commitment,
	}
	if err := zksch.save(sch); err != nil {
		return err
	}

	return nil
}

func (zksch *ZKSchnorr) Prove(hash hash.Hash, secret curve.Scalar, public curve.Point) (curve.Scalar, error) {
	sch, err := zksch.get()
	if err != nil {
		return nil, err
	}

	if sch.group == nil {
		return nil, errors.New("group is nil")
	}
	if sch.alpha == nil || sch.bigAlpha == nil {
		return nil, errors.New("commitment is nil")
	}

	g := sch.group.NewBasePoint()

	if public.IsIdentity() || secret.IsZero() {
		return nil, nil
	}

	c, err := challenge(hash, sch.group, sch.bigAlpha, public, g)
	if err != nil {
		return nil, err
	}

	cx := c.Mul(secret)
	z := cx.Add(sch.alpha)

	sch.z = z
	sch.c = c
	if err = zksch.save(sch); err != nil {
		return nil, err
	}

	return z, nil
}

func (zksch *ZKSchnorr) Verify(hash hash.Hash, public curve.Point, proof curve.Scalar) (bool, error) {
	sch, err := zksch.get()
	if err != nil {
		return false, err
	}
	g := sch.group.NewBasePoint()

	if proof == nil || !isValidProof(proof) || public.IsIdentity() {
		return false, errors.New("invalid proof")
	}

	e, err := challenge(hash, sch.group, sch.bigAlpha, public, g)
	if err != nil {
		return false, err
	}

	lhs := proof.Act(g)
	rhs := e.Act(public)
	rhs = rhs.Add(sch.bigAlpha)

	sch.z = proof
	if err = zksch.save(sch); err != nil {
		return false, err
	}

	return lhs.Equal(rhs), nil
}

func (zksch *ZKSchnorr) Commitment() (curve.Point, error) {
	return zksch.bigAlpha, nil
}

func (zksch *ZKSchnorr) Proof() (curve.Scalar, error) {
	return zksch.z, nil
}

func isValidCommitment(c curve.Point) bool {
	if c == nil || c.IsIdentity() {
		return false
	}
	return true
}

func isValidProof(z curve.Scalar) bool {
	if z == nil || z.IsZero() {
		return false
	}
	return true
}

func challenge(hash hash.Hash, group curve.Curve, commitment, public, gen curve.Point) (e curve.Scalar, err error) {
	err = hash.WriteAny(commitment, public, gen)
	e = sample.Scalar(hash.Digest(), group)
	return
}

func (zksch ZKSchnorr) bytes() ([]byte, error) {
	group := zksch.group.Name()

	alpha, err := zksch.alpha.MarshalBinary()
	if err != nil {
		return nil, err
	}

	bigAlpha, err := zksch.bigAlpha.MarshalBinary()
	if err != nil {
		return nil, err
	}

	c, err := zksch.c.MarshalBinary()
	if err != nil {
		return nil, err
	}

	z, err := zksch.z.MarshalBinary()
	if err != nil {
		return nil, err
	}

	raw := rawZKSchnorr{
		Group:    group,
		Alpha:    alpha,
		BigAlpha: bigAlpha,
		C:        c,
		Z:        z,
	}

	return cbor.Marshal(raw)
}

func fromBytes(data []byte) (*ZKSchnorr, error) {
	var raw rawZKSchnorr
	if err := cbor.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	var group curve.Curve
	switch raw.Group {
	case "secp256k1":
		group = curve.Secp256k1{}
	}

	alpha := group.NewScalar()
	if err := alpha.UnmarshalBinary(raw.Alpha); err != nil {
		return nil, err
	}

	bigAlpha := group.NewPoint()
	if err := bigAlpha.UnmarshalBinary(raw.BigAlpha); err != nil {
		return nil, err
	}

	c := group.NewScalar()
	if err := c.UnmarshalBinary(raw.C); err != nil {
		return nil, err
	}

	z := group.NewScalar()
	if err := z.UnmarshalBinary(raw.Z); err != nil {
		return nil, err
	}

	return &ZKSchnorr{
		alpha:    alpha,
		bigAlpha: bigAlpha,
		c:        c,
		z:        z,
	}, nil
}

func (zksch *ZKSchnorr) save(sch *ZKSchnorr) error {
	sch_bytes, err := sch.bytes()
	if err != nil {
		return err
	}
	if err := zksch.store.Import(sch_bytes); err != nil {
		return err
	}
	return nil
}

func (zksch *ZKSchnorr) get() (*ZKSchnorr, error) {
	sch_bytes, err := zksch.store.Get()
	if err != nil {
		return nil, err
	}
	return fromBytes(sch_bytes)
}
