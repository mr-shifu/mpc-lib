package arith

import (
	"encoding/binary"
	"errors"

	"github.com/cronokirby/saferith"
)

var (
	ErrEmptyEncodedData = errors.New("encoded modulus has empty data")
)

// Modulus wraps a saferith.Modulus and enables faster modular exponentiation when
// the factorization is known.
// When n = p⋅q, xᵉ (mod n) can be computed with only two exponentiations
// with p and q respectively.
type Modulus struct {
	// represents modulus n
	*saferith.Modulus
	// n = p⋅p
	p, q *saferith.Modulus
	// pInv = p⁻¹ (mod q)
	pNat, pInv *saferith.Nat
}

func NewEmptyModulus() *Modulus {
	return &Modulus{
		Modulus: new(saferith.Modulus),
		p:       new(saferith.Modulus),
		q:       new(saferith.Modulus),
		pNat:    new(saferith.Nat),
		pInv:    new(saferith.Nat),
	}
}

// ModulusFromN creates a simple wrapper around a given modulus n.
// The modulus is not copied.
func ModulusFromN(n *saferith.Modulus) *Modulus {
	return &Modulus{
		Modulus: n,
	}
}

// ModulusPhi returns a new Modulus from phi = (p-1)⋅(q-1).
func (n *Modulus) ModulusPhi() *saferith.Modulus {
	oneNat := new(saferith.Nat).SetUint64(1)
	pMinus1 := new(saferith.Nat).Sub(n.p.Nat(), oneNat, -1)
	qMinus1 := new(saferith.Nat).Sub(n.q.Nat(), oneNat, -1)
	phi := new(saferith.Nat).Mul(pMinus1, qMinus1, -1)
	return saferith.ModulusFromNat(phi)
}

// ModulusFromFactors creates the necessary cached values to accelerate
// exponentiation mod n.
func ModulusFromFactors(p, q *saferith.Nat) *Modulus {
	nNat := new(saferith.Nat).Mul(p, q, -1)
	nMod := saferith.ModulusFromNat(nNat)
	pMod := saferith.ModulusFromNat(p)
	qMod := saferith.ModulusFromNat(q)
	pInvQ := new(saferith.Nat).ModInverse(p, qMod)
	pNat := new(saferith.Nat).SetNat(p)
	return &Modulus{
		Modulus: nMod,
		p:       pMod,
		q:       qMod,
		pNat:    pNat,
		pInv:    pInvQ,
	}
}

// Exp is equivalent to (saferith.Nat).Exp(x, e, n.Modulus).
// It returns xᵉ (mod n).
func (n *Modulus) Exp(x, e *saferith.Nat) *saferith.Nat {
	if n.hasFactorization() {
		var xp, xq saferith.Nat
		xp.Exp(x, e, n.p) // x₁ = xᵉ (mod p₁)
		xq.Exp(x, e, n.q) // x₂ = xᵉ (mod p₂)
		// r = x₁ + p₁ ⋅ [p₁⁻¹ (mod p₂)] ⋅ [x₁ - x₂] (mod n)
		r := xq.ModSub(&xq, &xp, n.Modulus)
		r.ModMul(r, n.pInv, n.Modulus)
		r.ModMul(r, n.pNat, n.Modulus)
		r.ModAdd(r, &xp, n.Modulus)
		return r
	}
	return new(saferith.Nat).Exp(x, e, n.Modulus)
}

// ExpI is equivalent to (saferith.Nat).ExpI(x, e, n.Modulus).
// It returns xᵉ (mod n).
func (n *Modulus) ExpI(x *saferith.Nat, e *saferith.Int) *saferith.Nat {
	if n.hasFactorization() {
		y := n.Exp(x, e.Abs())
		inverted := new(saferith.Nat).ModInverse(y, n.Modulus)
		y.CondAssign(e.IsNegative(), inverted)
		return y
	}
	return new(saferith.Nat).ExpI(x, e, n.Modulus)
}

func (n Modulus) hasFactorization() bool {
	return n.p != nil && n.q != nil && n.pNat != nil && n.pInv != nil
}

func (n *Modulus) MarshalBinary() ([]byte, error) {
	nb, err := n.Modulus.MarshalBinary()
	if err != nil {
		return nil, err
	}
	pb, err := n.p.MarshalBinary()
	if err != nil {
		return nil, err
	}
	qb, err := n.q.MarshalBinary()
	if err != nil {
		return nil, err
	}
	pinvb, err := n.pInv.MarshalBinary()
	if err != nil {
		return nil, err
	}
	pnatb, err := n.pNat.MarshalBinary()
	if err != nil {
		return nil, err
	}

	nlb := make([]byte, 2)
	binary.LittleEndian.PutUint16(nlb, uint16(len(nb)))

	plb := make([]byte, 2)
	binary.LittleEndian.PutUint16(plb, uint16(len(pb)))

	qlb := make([]byte, 2)
	binary.LittleEndian.PutUint16(qlb, uint16(len(qb)))

	pinvlb := make([]byte, 2)
	binary.LittleEndian.PutUint16(pinvlb, uint16(len(pinvb)))

	pnatlb := make([]byte, 2)
	binary.LittleEndian.PutUint16(pnatlb, uint16(len(pnatb)))

	buf := make(([]byte), 0)
	buf = append(buf, nlb...)
	buf = append(buf, nb...)
	buf = append(buf, plb...)
	buf = append(buf, pb...)
	buf = append(buf, qlb...)
	buf = append(buf, qb...)
	buf = append(buf, pinvlb...)
	buf = append(buf, pinvb...)
	buf = append(buf, pnatlb...)
	buf = append(buf, pnatb...)

	return buf, nil
}

func (n *Modulus) UnmarshalBinary(data []byte) error {
	if len(data) == 0 {
		return ErrEmptyEncodedData
	}
	nl := binary.LittleEndian.Uint16(data[:2])
	nb := new(saferith.Modulus)
	if err := nb.UnmarshalBinary(data[2 : 2+nl]); err != nil {
		return err
	}

	pl := binary.LittleEndian.Uint16(data[2+nl : 4+nl])
	p := new(saferith.Modulus)
	if err := p.UnmarshalBinary(data[4+nl : 4+nl+pl]); err != nil {
		return err
	}

	ql := binary.LittleEndian.Uint16(data[4+nl+pl : 6+nl+pl])
	q := new(saferith.Modulus)
	if err := q.UnmarshalBinary(data[6+nl+pl : 6+nl+pl+ql]); err != nil {
		return err
	}

	pinvl := binary.LittleEndian.Uint16(data[6+nl+pl+ql : 8+nl+pl+ql])
	pinv := new(saferith.Nat)
	if err := pinv.UnmarshalBinary(data[8+nl+pl+ql : 8+nl+pl+ql+pinvl]); err != nil {
		return err
	}

	pnatl := binary.LittleEndian.Uint16(data[8+nl+pl+ql+pinvl : 10+nl+pl+ql+pinvl])
	pnat := new(saferith.Nat)
	if err := pnat.UnmarshalBinary(data[10+nl+pl+ql+pinvl : 10+nl+pl+ql+pinvl+pnatl]); err != nil {
		return err
	}

	n.Modulus = nb
	n.p = p
	n.q = q
	n.pInv = pinv
	n.pNat = pnat

	return nil
}
