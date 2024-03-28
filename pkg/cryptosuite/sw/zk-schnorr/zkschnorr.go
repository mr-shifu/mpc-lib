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
	ErrKeyExists   = errors.New("zkschctore: key exists")
	ErrKeyNotFound = errors.New("zkschctore: key not found")
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

	zksch.group = group
	zksch.alpha = alpha
	zksch.bigAlpha = bigAlpha

	if err := zksch.save(); err != nil {
		return nil, err
	}

	return bigAlpha, nil
}

func (zksch *ZKSchnorr) ImportCommitment(commitment curve.Point, group curve.Curve) error {
	if commitment == nil {
		return errors.New("commitment is nil")
	}
	if !isValidCommitment(commitment) {
		return errors.New("invalid commitment")
	}

	zksch.group = group
	zksch.bigAlpha = commitment

	if err := zksch.save(); err != nil {
		return err
	}

	return nil
}

func (zksch *ZKSchnorr) Prove(hash hash.Hash, secret curve.Scalar, public curve.Point) (curve.Scalar, error) {
	err := zksch.get()
	if err != nil {
		return nil, err
	}

	if zksch.group == nil {
		return nil, errors.New("group is nil")
	}
	if zksch.alpha == nil || zksch.bigAlpha == nil {
		return nil, errors.New("commitment is nil")
	}

	g := zksch.group.NewBasePoint()

	if public.IsIdentity() || secret.IsZero() {
		return nil, nil
	}

	c, err := challenge(hash, zksch.group, zksch.bigAlpha, public, g)
	if err != nil {
		return nil, err
	}

	cx := c.Mul(secret)
	z := cx.Add(zksch.alpha)

	zksch.z = z
	zksch.c = c
	if err = zksch.save(); err != nil {
		return nil, err
	}

	return z, nil
}

func (zksch *ZKSchnorr) Verify(hash hash.Hash, public curve.Point, proof curve.Scalar) (bool, error) {
	if err := zksch.get(); err != nil {
		return false, err
	}
	g := zksch.group.NewBasePoint()

	if proof == nil || !isValidProof(proof) || public.IsIdentity() {
		return false, errors.New("invalid proof")
	}

	e, err := challenge(hash, zksch.group, zksch.bigAlpha, public, g)
	if err != nil {
		return false, err
	}

	lhs := proof.Act(g)
	rhs := e.Act(public)
	rhs = rhs.Add(zksch.bigAlpha)

	zksch.z = proof
	if err = zksch.save(); err != nil {
		return false, err
	}

	return lhs.Equal(rhs), nil
}

func (zksch *ZKSchnorr) Commitment() (curve.Point, error) {
	err := zksch.get()
	if err != nil {
		return nil, err
	}
	return zksch.bigAlpha, nil
}

func (zksch *ZKSchnorr) Proof() (curve.Scalar, error) {
	err := zksch.get()
	if err != nil {
		return nil, err
	}
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
	raw := &rawZKSchnorr{}

	group := zksch.group.Name()
	raw.Group = group

	if zksch.alpha != nil {
		alpha, err := zksch.alpha.MarshalBinary()
		if err != nil {
			return nil, err
		}
		raw.Alpha = alpha
	}

	if zksch.bigAlpha != nil {
		bigAlpha, err := zksch.bigAlpha.MarshalBinary()
		if err != nil {
			return nil, err
		}
		raw.BigAlpha = bigAlpha
	}

	if zksch.c != nil {
		c, err := zksch.c.MarshalBinary()
		if err != nil {
			return nil, err
		}
		raw.C = c
	}

	if zksch.z != nil {
		z, err := zksch.z.MarshalBinary()
		if err != nil {
			return nil, err
		}
		raw.Z = z
	}

	return cbor.Marshal(raw)
}

func fromBytes(data []byte, zksch *ZKSchnorr) (error) {
	// zksch := &ZKSchnorr{}

	var raw rawZKSchnorr
	if err := cbor.Unmarshal(data, &raw); err != nil {
		return err
	}

	var group curve.Curve
	switch raw.Group {
	case "secp256k1":
		group = curve.Secp256k1{}
		zksch.group = group
	}

	if raw.Alpha != nil {
		alpha := group.NewScalar()
		if err := alpha.UnmarshalBinary(raw.Alpha); err != nil {
			return err
		}
		zksch.alpha = alpha
	}

	if raw.BigAlpha != nil {
		bigAlpha := group.NewPoint()
		if err := bigAlpha.UnmarshalBinary(raw.BigAlpha); err != nil {
			return err
		}
		zksch.bigAlpha = bigAlpha
	}

	if raw.C != nil {
		c := group.NewScalar()
		if err := c.UnmarshalBinary(raw.C); err != nil {
			return err
		}
		zksch.c = c
	}

	if raw.Z != nil {
		z := group.NewScalar()
		if err := z.UnmarshalBinary(raw.Z); err != nil {
			return err
		}
		zksch.z = z
	}

	return nil
}

func (zksch *ZKSchnorr) save() error {
	sch_bytes, err := zksch.bytes()
	if err != nil {
		return err
	}
	if err := zksch.store.Import(sch_bytes); err != nil {
		return err
	}
	return nil
}

func (zksch *ZKSchnorr) get() error {
	sch_bytes, err := zksch.store.Get()
	if err != nil {
		return err
	}

	if err := fromBytes(sch_bytes, zksch); err != nil {
		return err
	}

	return err
}
