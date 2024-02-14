package arith

import (
	"encoding/json"

	"github.com/cronokirby/saferith"
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

type ModulusSerilized struct {
	Modulus []byte
	P       []byte
	Q       []byte
	PNat    []byte
	PInv    []byte
}

func (n *Modulus) Serialize() ([]byte, error) {
	var ns ModulusSerilized
	ns.Modulus = n.Modulus.Bytes()
	if n.p != nil {
		ns.P = n.p.Bytes()
	}
	if n.q != nil {
		ns.Q = n.q.Bytes()
	}
	if n.pNat != nil {
		ns.PNat = n.pNat.Bytes()
	}
	if n.pInv != nil {
		ns.PInv = n.pInv.Bytes()
	}
	return json.Marshal(ns)
}

func (n *Modulus) Deserialize(data []byte) error {
	var ns ModulusSerilized
	err := json.Unmarshal(data, &ns)
	if err != nil {
		return err
	}
	n.Modulus = new(saferith.Modulus)
	if err := n.Modulus.UnmarshalBinary(ns.Modulus); err != nil {
		return err
	}

	if ns.P != nil {
		if err := n.p.UnmarshalBinary(ns.P); err != nil {
			return err
		}
	} else {
		n.p = nil
	}

	if ns.Q != nil {
		if err := n.q.UnmarshalBinary(ns.Q); err != nil {
			return err
		}
	} else {
		n.q = nil
	}

	if ns.PInv != nil {
		if err := n.pInv.UnmarshalBinary(ns.PInv); err != nil {
			return err
		}
	} else {
		n.pInv = nil
	}

	if ns.PNat != nil {
		if err := n.pNat.UnmarshalBinary(ns.PNat); err != nil {
			return err
		}
	} else {
		n.pNat = nil
	}

	return nil
}
