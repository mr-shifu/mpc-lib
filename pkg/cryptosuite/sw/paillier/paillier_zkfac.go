package paillier

import (
	"crypto/rand"

	"github.com/cronokirby/saferith"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
	"github.com/mr-shifu/mpc-lib/core/math/arith"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
	zkfac "github.com/mr-shifu/mpc-lib/core/zk/fac"
)

func (k PaillierKey) NewZKFACProof(hash hash.Hash, public zkfac.Public) *zkfac.Proof {
	Nhat := public.Aux.NArith()

	// Figure 28, point 1.
	alpha := sample.IntervalLEpsRootN(rand.Reader)
	beta := sample.IntervalLEpsRootN(rand.Reader)
	mu := sample.IntervalLN(rand.Reader)
	nu := sample.IntervalLN(rand.Reader)
	sigma := sample.IntervalLN2(rand.Reader)
	r := sample.IntervalLEpsN2(rand.Reader)
	x := sample.IntervalLEpsN(rand.Reader)
	y := sample.IntervalLEpsN(rand.Reader)

	pInt := new(saferith.Int).SetNat(k.secretKey.P())
	qInt := new(saferith.Int).SetNat(k.secretKey.Q())
	P := public.Aux.Commit(pInt, mu)
	Q := public.Aux.Commit(qInt, nu)
	A := public.Aux.Commit(alpha, x)
	B := public.Aux.Commit(beta, y)
	T := Nhat.ExpI(Q, alpha)
	T.ModMul(T, Nhat.ExpI(public.Aux.T(), r), Nhat.Modulus)

	comm := zkfac.Commitment{
		P: P,
		Q: Q,
		A: A,
		B: B,
		T: T,
	}

	// Figure 28, point 2:
	e, _ := zkfac_challenge(hash, public, comm)

	// Figure 28, point 3:
	// "..., and sends (z, u, v) to the verifier, where"
	// DEVIATION:
	// This seems like another typo, because there's no "u",
	// so I assume they meant "sends (z1, z2, w1, w2, v)".
	z1 := new(saferith.Int).Mul(e, pInt, -1)
	z1.Add(z1, alpha, -1)
	z2 := new(saferith.Int).Mul(e, qInt, -1)
	z2.Add(z2, beta, -1)
	w1 := new(saferith.Int).Mul(e, mu, -1)
	w1.Add(w1, x, -1)
	w2 := new(saferith.Int).Mul(e, nu, -1)
	w2.Add(w2, y, -1)
	sigmaHat := new(saferith.Int).Mul(nu, pInt, -1)
	sigmaHat = sigmaHat.Neg(1)
	sigmaHat.Add(sigmaHat, sigma, -1)
	v := new(saferith.Int).Mul(e, sigmaHat, -1)
	v.Add(v, r, -1)

	return &zkfac.Proof{
		Comm:  comm,
		Sigma: sigma,
		Z1:    z1,
		Z2:    z2,
		W1:    w1,
		W2:    w2,
		V:     v,
	}
}

func (k PaillierKey) VerifyZKFAC(p *zkfac.Proof, public zkfac.Public, hash hash.Hash) bool {
	if p == nil {
		return false
	}

	e, err := zkfac_challenge(hash, public, p.Comm)
	if err != nil {
		return false
	}

	N0 := public.N
	NhatArith := public.Aux.NArith()
	Nhat := NhatArith.Modulus

	if !public.Aux.Verify(p.Z1, p.W1, e, p.Comm.A, p.Comm.P) {
		return false
	}

	if !public.Aux.Verify(p.Z2, p.W2, e, p.Comm.B, p.Comm.Q) {
		return false
	}

	// Setting R this way avoid issues with the other exponent functions which
	// might try and apply the CRT.
	R := new(saferith.Nat).SetNat(public.Aux.S())
	R = NhatArith.Exp(R, N0.Nat())
	R.ModMul(R, NhatArith.ExpI(public.Aux.T(), p.Sigma), Nhat)

	lhs := NhatArith.ExpI(p.Comm.Q, p.Z1)
	lhs.ModMul(lhs, NhatArith.ExpI(public.Aux.T(), p.V), Nhat)
	rhs := NhatArith.ExpI(R, e)
	rhs.ModMul(rhs, p.Comm.T, Nhat)
	if lhs.Eq(rhs) != 1 {
		return false
	}

	// DEVIATION: for the bounds to work, we add an extra bit, to ensure that we don't have spurious failures.
	return arith.IsInIntervalLEpsPlus1RootN(p.Z1) && arith.IsInIntervalLEpsPlus1RootN(p.Z2)
}

func zkfac_challenge(hash hash.Hash, public zkfac.Public, commitment zkfac.Commitment) (*saferith.Int, error) {
	err := hash.WriteAny(public.N, public.Aux, commitment.P, commitment.Q, commitment.A, commitment.B, commitment.T)
	if err != nil {
		return nil, err
	}
	// Figure 28, point 2:
	// "Verifier replies with e <- +-q"
	// DEVIATION:
	// This doesn't make any sense, since we don't know the secret factor q,
	// and involving the size of scalars doesn't make sense.
	// I think that this is a typo in the paper, and instead it should
	// be +-2^eps.
	return sample.IntervalL(hash.Digest()), nil
}
