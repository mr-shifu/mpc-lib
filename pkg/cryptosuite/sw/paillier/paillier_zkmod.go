package paillier

import (
	"crypto/rand"

	"math/big"

	"github.com/cronokirby/saferith"
	"github.com/mr-shifu/mpc-lib/core/hash"
	"github.com/mr-shifu/mpc-lib/core/math/arith"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
	"github.com/mr-shifu/mpc-lib/core/pool"
	zkmod "github.com/mr-shifu/mpc-lib/core/zk/mod"
	"github.com/mr-shifu/mpc-lib/lib/params"
)

func (k PaillierKey) NewZKModProof(hash *hash.Hash, pl *pool.Pool) *zkmod.Proof {
	n := k.publicKey.N()
	p := k.secretKey.P()
	q := k.secretKey.Q()
	phi := k.secretKey.Phi()

	nModulus := arith.ModulusFromFactors(p, q)
	pHalf := new(saferith.Nat).Rsh(p, 1, -1)
	pMod := saferith.ModulusFromNat(p)
	qHalf := new(saferith.Nat).Rsh(q, 1, -1)
	qMod := saferith.ModulusFromNat(q)
	phiMod := saferith.ModulusFromNat(phi)
	// W can be leaked so no need to make this sampling return a nat.
	w := sample.QNR(rand.Reader, n)

	nInverse := new(saferith.Nat).ModInverse(n.Nat(), phiMod)

	e := fourthRootExponent(phi)

	ys, _ := challenge(hash, n, w.Big())

	var rs [params.StatParam]zkmod.Response
	pl.Parallelize(params.StatParam, func(i int) interface{} {
		y := ys[i]

		// Z = y^{n⁻¹ (mod n)}
		z := nModulus.Exp(y, nInverse)

		a, b, yPrime := makeQuadraticResidue(y, w, pHalf, qHalf, n, pMod, qMod)
		// X = (y')¹/4
		x := nModulus.Exp(yPrime, e)

		rs[i] = zkmod.Response{
			A: a,
			B: b,
			X: x.Big(),
			Z: z.Big(),
		}

		return nil
	})

	return &zkmod.Proof{
		W:         w.Big(),
		Responses: rs,
	}
}

func (k PaillierKey) VerifyZKMod(p *zkmod.Proof, hash *hash.Hash, pl *pool.Pool) bool {
	if p == nil {
		return false
	}
	n := k.publicKey.N().Big()
	nMod := k.publicKey.N()

	// check if n is odd and prime
	if n.Bit(0) == 0 || n.ProbablyPrime(20) {
		return false
	}

	if big.Jacobi(p.W, n) != -1 {
		return false
	}

	if !arith.IsValidBigModN(n, p.W) {
		return false
	}

	// get [yᵢ] <- ℤₙ
	ys, err := challenge(hash, nMod, p.W)
	if err != nil {
		return false
	}
	verifications := pl.Parallelize(params.StatParam, func(i int) interface{} {
		return verifyResponse(p.Responses[i], n, p.W, ys[i].Big())
	})
	for i := 0; i < len(verifications); i++ {
		if !verifications[i].(bool) {
			return false
		}
	}
	return true
}

func verifyResponse(r zkmod.Response, n, w, y *big.Int) bool {
	var lhs, rhs big.Int

	// lhs = zⁿ mod n
	lhs.Exp(r.Z, n, n)
	if lhs.Cmp(y) != 0 {
		return false
	}

	// lhs = x⁴ (mod n)
	lhs.Mul(r.X, r.X)
	lhs.Mul(&lhs, &lhs)
	lhs.Mod(&lhs, n)

	// rhs = y' = (-1)ᵃ • wᵇ • y
	rhs.Set(y)
	if r.A {
		rhs.Neg(&rhs)
	}
	if r.B {
		rhs.Mul(&rhs, w)
	}
	rhs.Mod(&rhs, n)

	return lhs.Cmp(&rhs) == 0
}

// makeQuadraticResidue return a, b and y' such that:
//
//	 y' = (-1)ᵃ • wᵇ • y
//	is a QR.
//
// With:
//   - n=pq is a blum integer
//   - w is a quadratic non residue in Zn
//   - y is an element that may or may not be a QR
//   - pHalf = (p - 1) / 2
//   - qHalf = (p - 1) / 2
//
// Leaking the return values is fine, but not the input values related to the factorization of N.
func makeQuadraticResidue(y, w, pHalf, qHalf *saferith.Nat, n, p, q *saferith.Modulus) (a, b bool, out *saferith.Nat) {
	out = new(saferith.Nat).Mod(y, n)

	if isQRmodPQ(out, pHalf, qHalf, p, q) == 1 {
		return
	}

	// multiply by -1
	out.ModNeg(out, n)
	a, b = true, false
	if isQRmodPQ(out, pHalf, qHalf, p, q) == 1 {
		return
	}

	// multiply by w again
	out.ModMul(out, w, n)
	a, b = true, true
	if isQRmodPQ(out, pHalf, qHalf, p, q) == 1 {
		return
	}

	// multiply by -1 again
	out.ModNeg(out, n)
	a, b = false, true
	return
}

// isQRModPQ checks that y is a quadratic residue mod both p and q.
//
// p and q should be prime numbers.
//
// pHalf should be (p - 1) / 2
//
// qHalf should be (q - 1) / 2.
func isQRmodPQ(y, pHalf, qHalf *saferith.Nat, p, q *saferith.Modulus) saferith.Choice {
	oneNat := new(saferith.Nat).SetUint64(1).Resize(1)

	test := new(saferith.Nat)
	test.Exp(y, pHalf, p)
	pOk := test.Eq(oneNat)

	test.Exp(y, qHalf, q)
	qOk := test.Eq(oneNat)

	return pOk & qOk
}

func fourthRootExponent(phi *saferith.Nat) *saferith.Nat {
	e := new(saferith.Nat).SetUint64(4)
	e.Add(e, phi, -1)
	e.Rsh(e, 3, -1)
	e.ModMul(e, e, saferith.ModulusFromNat(phi))
	return e
}

func challenge(hash *hash.Hash, n *saferith.Modulus, w *big.Int) (es []*saferith.Nat, err error) {
	err = hash.WriteAny(n, w)
	es = make([]*saferith.Nat, params.StatParam)
	for i := range es {
		es[i] = sample.ModN(hash.Digest(), n)
	}
	return
}
