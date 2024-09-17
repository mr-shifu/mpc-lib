package test

// import (
// 	"io"

// 	"github.com/mr-shifu/mpc-lib/core/math/curve"
// 	"github.com/mr-shifu/mpc-lib/core/math/polynomial"
// 	"github.com/mr-shifu/mpc-lib/core/math/sample"
// 	"github.com/mr-shifu/mpc-lib/core/paillier"
// 	"github.com/mr-shifu/mpc-lib/core/party"
// 	"github.com/mr-shifu/mpc-lib/core/pedersen"
// 	"github.com/mr-shifu/mpc-lib/core/pool"
// 	"github.com/mr-shifu/mpc-lib/lib/types"
// 	"github.com/mr-shifu/mpc-lib/protocols/cmp/keygen"
// )

// // GenerateConfig creates some random configuration for N parties with set threshold T over the group.
// func GenerateConfig(group curve.Curve, N, T int, source io.Reader, pl *pool.Pool) (map[party.ID]*keygen.Config, party.IDSlice) {
// 	partyIDs := PartyIDs(N)
// 	configs := make(map[party.ID]*keygen.Config, N)
// 	public := make(map[party.ID]*keygen.Public, N)

// 	f := polynomial.NewPolynomial(group, T, sample.Scalar(source, group))

// 	rid, err := types.NewRID(source)
// 	if err != nil {
// 		panic(err)
// 	}
// 	chainKey, err := types.NewRID(source)
// 	if err != nil {
// 		panic(err)
// 	}

// 	for _, pid := range partyIDs {
// 		paillierSecret := paillier.NewSecretKey(pl)
// 		s, t, _ := sample.Pedersen(source, paillierSecret.Phi(), paillierSecret.N())
// 		pedersenPublic := pedersen.New(paillierSecret.Modulus(), s, t)
// 		elGamalSecret := sample.Scalar(source, group)

// 		ecdsaSecret := f.Evaluate(pid.Scalar(group))
// 		configs[pid] = &keygen.Config{
// 			Group:     group,
// 			ID:        pid,
// 			Threshold: T,
// 			ECDSA:     ecdsaSecret,
// 			ElGamal:   elGamalSecret,
// 			Paillier:  paillierSecret,
// 			RID:       rid.Copy(),
// 			ChainKey:  chainKey.Copy(),
// 			Public:    public,
// 		}
// 		X := ecdsaSecret.ActOnBase()
// 		public[pid] = &keygen.Public{
// 			ECDSA:    X,
// 			ElGamal:  elGamalSecret.ActOnBase(),
// 			Paillier: paillierSecret.PublicKey,
// 			Pedersen: pedersenPublic,
// 		}
// 	}
// 	return configs, partyIDs
// }
