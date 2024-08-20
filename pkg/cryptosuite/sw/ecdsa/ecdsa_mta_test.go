package ecdsa

import (
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	paillier_core "github.com/mr-shifu/mpc-lib/core/paillier"
	"github.com/mr-shifu/mpc-lib/core/pool"
	zkaffg "github.com/mr-shifu/mpc-lib/core/zk/affg"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillier"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillierencodedkey"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/pedersen"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/vault"
	"github.com/stretchr/testify/assert"
)

type MtAResult struct {
	beta   *saferith.Int
	alpha  *saferith.Int
	alphaD *paillier_core.Ciphertext
	proof  *zkaffg.Proof
}

func TestMtA(t *testing.T) {
	pl := pool.NewPool(0)

	group := curve.Secp256k1{}

	partyIDs := []string{"a", "b", "c"}

	opts, err := keyopts.NewOptions().Set("id", "123", "partyid", "a")
	assert.NoError(t, err)

	hash_vault := vault.NewInMemoryVault()
	hash_kr := keyopts.NewInMemoryKeyOpts()
	hs := keystore.NewInMemoryKeystore(hash_vault, hash_kr)
	mgr := hash.NewHashManager(hs)
	h := mgr.NewHasher("123", opts)

	paillier_vault := vault.NewInMemoryVault()
	paillier_kr := keyopts.NewInMemoryKeyOpts()
	paillier_ks := keystore.NewInMemoryKeystore(paillier_vault, paillier_kr)
	paillier_km := paillier.NewPaillierKeyManager(paillier_ks, pl)

	vss_vault := vault.NewInMemoryVault()
	vss_kr := keyopts.NewInMemoryKeyOpts()
	vss_ks := keystore.NewInMemoryKeystore(vss_vault, vss_kr)
	vss_km := vss.NewVssKeyManager(vss_ks, curve.Secp256k1{})

	// mta_ks := keystore.NewInMemoryKeystore()
	// mta_mgr := mta.NewMtAManager(mta_ks)

	ecdsa_vault := vault.NewInMemoryVault()
	ecdsa_kr := keyopts.NewInMemoryKeyOpts()
	ecdsa_ks := keystore.NewInMemoryKeystore(ecdsa_vault, ecdsa_kr)

	sch_vault := vault.NewInMemoryVault()
	sch_kr := keyopts.NewInMemoryKeyOpts()
	sch_ks := keystore.NewInMemoryKeystore(sch_vault, sch_kr)

	ec_km := NewECDSAKeyManager(ecdsa_ks, sch_ks, vss_km, &Config{Group: curve.Secp256k1{}})

	pks := make(map[string]paillier.PaillierKey, 0)
	peds := make(map[string]pedersen.PedersenKey, 0)
	ks := make(map[string]*ECDSAKeyImpl, 0)
	gammas := make(map[string]*ECDSAKeyImpl, 0)
	Gs := make(map[string]paillierencodedkey.PaillierEncodedKey, 0)
	Ks := make(map[string]paillierencodedkey.PaillierEncodedKey, 0)

	for _, party := range partyIDs {
		pk, _ := paillier_km.GenerateKey(opts)
		pks[party] = pk

		ped, _ := pk.DerivePedersenKey()
		peds[party] = ped

		opts, err := keyopts.NewOptions().Set("id", "123", "partyid", party)
		assert.NoError(t, err)

		gamma, _ := ec_km.GenerateKey(opts)
		gammas[party] = gamma.(*ECDSAKeyImpl)

		G, _ := gamma.EncodeByPaillier(pk.PublicKey())
		Gs[party] = G.(*paillierencodedkey.PaillierEncodedKeyImpl)

		k, _ := ec_km.GenerateKey(opts)
		ks[party] = k.(*ECDSAKeyImpl)

		K, _ := k.EncodeByPaillier(pk.PublicKey())
		Ks[party] = K.(*paillierencodedkey.PaillierEncodedKeyImpl)
	}

	mtaResults := make(map[string]map[string]MtAResult)
	for _, i := range partyIDs {
		mtaResults[i] = make(map[string]MtAResult, 0)
		for _, j := range partyIDs {
			if j == i {
				continue
			}

			gamma := gammas[i]
			Kj := Ks[j]
			pk := pks[i]
			pkj := pks[j]
			pedj := peds[j]

			beta, alphaD, _, proof := gamma.NewMtAAffgProof(
				h.Clone(),
				Kj.Encoded(),
				pk.PublicKey(),
				pkj.PublicKey(),
				pedj.PublicKey(),
			)
			alpha, _ := pkj.Decode(alphaD)
			mtaResults[i][j] = MtAResult{
				beta:   beta,
				alpha:  alpha,
				alphaD: alphaD,
				proof:  proof,
			}
		}
	}

	deltas := make(map[string]curve.Scalar)
	for _, i := range partyIDs {
		mtaResult := mtaResults[i]
		gamma := gammas[i]
		k := ks[i]
		deltaSum := new(saferith.Int)
		for _, res := range mtaResult {
			deltaSum = deltaSum.Add(deltaSum, res.beta, -1)
			deltaSum = deltaSum.Add(deltaSum, res.alpha, -1)
		}
		deltaScalar := gamma.CommitByKey(k, group.NewScalar().SetNat(deltaSum.Mod(group.Order())))
		// delta := new(saferith.Int).Mul(curve.MakeInt(gamma.priv), curve.MakeInt(k.priv), -1)
		// delta = delta.Add(delta, deltaSum, -1)
		// deltaScalar := group.NewScalar().SetNat(delta.Mod(group.Order()))
		deltas[i] = deltaScalar
	}

	deltaInt := new(saferith.Int)
	for _, i := range partyIDs {
		deltaInt = deltaInt.Add(deltaInt, curve.MakeInt(deltas[i]), -1)
	}
	delta := group.NewScalar().SetNat(deltaInt.Mod(group.Order()))

	gammaInt := new(saferith.Int)
	gamma := group.NewScalar()
	bigGamma := group.NewPoint()
	for _, gammaj := range gammas {
		gammaInt = gammaInt.Add(gammaInt, curve.MakeInt(gammaj.priv), -1)
		gamma = group.NewScalar().SetNat(gammaInt.Mod(group.Order()))
		bigGamma = bigGamma.Add(gammaj.pub)

		assert.True(t, gammaj.priv.ActOnBase().Equal(gammaj.pub))
		assert.True(t, gamma.ActOnBase().Equal(bigGamma))
	}

	kInt := new(saferith.Int)
	bigDeltas := make(map[string]curve.Point)
	k := group.NewScalar()
	for _, party := range partyIDs {
		kj := ks[party]
		kInt = kInt.Add(kInt, curve.MakeInt(kj.priv), -1)
		k = group.NewScalar().SetNat(kInt.Mod(group.Order()))

		bigDeltas[party] = kj.priv.Act(bigGamma)
	}

	bigDelta := group.NewPoint()
	for _, delta := range bigDeltas {
		bigDelta = bigDelta.Add(delta)
	}

	bigGammaComputed := gamma.ActOnBase()
	assert.True(t, bigGammaComputed.Equal(bigGamma))

	deltaComputed := k.Mul(gamma)
	bigDeltaComputed := deltaComputed.ActOnBase()

	assert.True(t, deltaComputed.Equal(delta))
	assert.True(t, delta.ActOnBase().Equal(bigDeltaComputed))
	assert.True(t, delta.ActOnBase().Equal(bigDelta))
}
