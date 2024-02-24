package pedersen

import (
	"crypto/rand"
	"io"
	"math/big"

	"github.com/cronokirby/saferith"
	"github.com/mr-shifu/mpc-lib/core/hash"
	"github.com/mr-shifu/mpc-lib/core/math/arith"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
	"github.com/mr-shifu/mpc-lib/core/pedersen"
	pedersencore "github.com/mr-shifu/mpc-lib/core/pedersen"
	"github.com/mr-shifu/mpc-lib/core/pool"
	"github.com/mr-shifu/mpc-lib/lib/params"
	cs_pedersen "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/pedersen"
)

// NewProof generates a proof that:
// s = t^lambda (mod N).
func (k PedersenKey) NewProof(hash *hash.Hash, pl *pool.Pool) *cs_pedersen.Proof {
	n := k.public.NArith()
	phi := n.ModulusPhi()

	var (
		as [params.StatParam]*saferith.Nat
		As [params.StatParam]*big.Int
	)
	lockedRand := pool.NewLockedReader(rand.Reader)
	pl.Parallelize(params.StatParam, func(i int) interface{} {
		// aᵢ ∈ mod ϕ(N)
		as[i] = sample.ModN(lockedRand, phi)

		// Aᵢ = tᵃ mod N
		As[i] = n.Exp(k.public.T(), as[i]).Big()

		return nil
	})

	es, _ := challenge(hash, k.public, As)
	// Modular addition is not expensive enough to warrant parallelizing
	var Zs [params.StatParam]*big.Int
	for i := 0; i < params.StatParam; i++ {
		z := as[i]
		// The challenge is public, so branching is ok
		if es[i] {
			z.ModAdd(z, k.secret, phi)
		}
		Zs[i] = z.Big()
	}

	return &cs_pedersen.Proof{
		As: As,
		Zs: Zs,
	}
}

func (k PedersenKey) VerifyProof(hash *hash.Hash, pl *pool.Pool, p *cs_pedersen.Proof) bool {
	if p == nil {
		return false
	}
	if err := pedersen.ValidateParameters(k.public.N(), k.public.S(), k.public.T()); err != nil {
		return false
	}

	n, s, t := k.public.N().Big(), k.public.S().Big(), k.public.T().Big()

	es, err := challenge(hash, k.public, p.As)
	if err != nil {
		return false
	}

	one := big.NewInt(1)
	verifications := pl.Parallelize(params.StatParam, func(i int) interface{} {
		var lhs, rhs big.Int
		z := p.Zs[i]
		a := p.As[i]

		if !arith.IsValidBigModN(n, a, z) {
			return false
		}

		if a.Cmp(one) == 0 {
			return false
		}

		lhs.Exp(t, z, n)
		if es[i] {
			rhs.Mul(a, s)
			rhs.Mod(&rhs, n)
		} else {
			rhs.Set(a)
		}

		if lhs.Cmp(&rhs) != 0 {
			return false
		}

		return true
	})
	for i := 0; i < len(verifications); i++ {
		ok, _ := verifications[i].(bool)
		if !ok {
			return false
		}
	}
	return true
}

func challenge(hash *hash.Hash, public *pedersencore.Parameters, A [params.StatParam]*big.Int) (es []bool, err error) {
	err = hash.WriteAny(public)
	for _, a := range A {
		_ = hash.WriteAny(a)
	}

	tmpBytes := make([]byte, params.StatParam)
	_, _ = io.ReadFull(hash.Digest(), tmpBytes)

	es = make([]bool, params.StatParam)
	for i := range es {
		b := (tmpBytes[i] & 1) == 1
		es[i] = b
	}

	return
}
