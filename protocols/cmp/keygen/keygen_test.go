package keygen

import (
	"fmt"
	mrand "math/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/pool"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/lib/test"
	"github.com/mr-shifu/mpc-lib/pkg/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/commitment"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/mpckey"
	"github.com/mr-shifu/mpc-lib/protocols/cmp/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sw_elgamal "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/elgamal"
	mpc_elgamal "github.com/mr-shifu/mpc-lib/pkg/mpc/elgamal"

	sw_paillier "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillier"
	mpc_paillier "github.com/mr-shifu/mpc-lib/pkg/mpc/paillier"

	sw_pedersen "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/pedersen"
	mpc_pedersen "github.com/mr-shifu/mpc-lib/pkg/mpc/pedersen"

	sw_rid "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/rid"
	mpc_rid "github.com/mr-shifu/mpc-lib/pkg/mpc/rid"

	sw_vss "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss"

	sw_ecdsa "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ecdsa"
	mpc_ecdsa "github.com/mr-shifu/mpc-lib/pkg/mpc/ecdsa"

	sw_hash "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"

	inmem_commitstore "github.com/mr-shifu/mpc-lib/pkg/commitstore"
	inmem_keyrepo "github.com/mr-shifu/mpc-lib/pkg/keyrepository"
)

var group = curve.Secp256k1{}

func checkOutput(t *testing.T, rounds []round.Session) {
	N := len(rounds)
	newConfigs := make([]*config.Config, 0, N)
	for _, r := range rounds {
		require.IsType(t, &round.Output{}, r)
		resultRound := r.(*round.Output)
		require.IsType(t, &config.Config{}, resultRound.Result)
		c := resultRound.Result.(*config.Config)
		marshalledConfig, err := cbor.Marshal(c)
		require.NoError(t, err)
		unmarshalledConfig := config.EmptyConfig(group)
		err = cbor.Unmarshal(marshalledConfig, unmarshalledConfig)
		require.NoError(t, err)
		newConfigs = append(newConfigs, unmarshalledConfig)
	}

	firstConfig := newConfigs[0]
	pk := firstConfig.PublicPoint()
	for _, c := range newConfigs {
		assert.True(t, pk.Equal(c.PublicPoint()), "RID is different")
		assert.Equal(t, firstConfig.RID, c.RID, "RID is different")
		assert.EqualValues(t, firstConfig.ChainKey, c.ChainKey, "ChainKey is different")
		for id, p := range firstConfig.Public {
			assert.True(t, p.ECDSA.Equal(c.Public[id].ECDSA), "ecdsa not the same", id)
			assert.True(t, p.ElGamal.Equal(c.Public[id].ElGamal), "elgamal not the same", id)
			assert.True(t, p.Paillier.Equal(c.Public[id].Paillier), "paillier not the same", id)
			assert.True(t, p.Pedersen.S().Eq(c.Public[id].Pedersen.S()) == 1, "S not the same", id)
			assert.True(t, p.Pedersen.T().Eq(c.Public[id].Pedersen.T()) == 1, "T not the same", id)
			assert.True(t, p.Pedersen.N().Nat().Eq(c.Public[id].Pedersen.N().Nat()) == 1, "N not the same", id)
		}
		data, err := c.MarshalBinary()
		assert.NoError(t, err, "failed to marshal new config", c.ID)
		c2 := config.EmptyConfig(group)
		err = c2.UnmarshalBinary(data)
		assert.NoError(t, err, "failed to unmarshal new config", c.ID)
	}
}

func newMPCKeygen() *MPCKeygen {
	pl := pool.NewPool(0)

	mpc_ks := mpckey.NewInMemoryMPCKeystore()

	elgamal_kr := inmem_keyrepo.NewKeyRepository()
	elgamal_ks := keystore.NewInMemoryKeystore()
	elgamal_km := sw_elgamal.NewElgamalKeyManager(elgamal_ks, &sw_elgamal.Config{Group: curve.Secp256k1{}})
	elgamal := mpc_elgamal.NewElgamal(elgamal_km, elgamal_kr)

	paillier_kr := inmem_keyrepo.NewKeyRepository()
	paillier_ks := keystore.NewInMemoryKeystore()
	paillier_km := sw_paillier.NewPaillierKeyManager(paillier_ks, pl)
	paillier := mpc_paillier.NewPaillierKeyManager(paillier_km, paillier_kr)

	pedersen_kr := inmem_keyrepo.NewKeyRepository()
	pedersen_ks := keystore.NewInMemoryKeystore()
	pedersen_km := sw_pedersen.NewPedersenKeymanager(pedersen_ks)
	pedersen := mpc_pedersen.NewPedersenKeyManager(pedersen_km, pedersen_kr)

	vss_kr := inmem_keyrepo.NewKeyRepository()
	vss_ks := keystore.NewInMemoryKeystore()
	vss_km := sw_vss.NewVssKeyManager(vss_ks, curve.Secp256k1{})

	ecdsa_ks := keystore.NewInMemoryKeystore()
	ecdsa_kr := inmem_keyrepo.NewKeyRepository()
	sch_ks := keystore.NewInMemoryKeystore()
	ecdsa_km := sw_ecdsa.NewECDSAKeyManager(ecdsa_ks, sch_ks, vss_km, &sw_ecdsa.Config{Group: curve.Secp256k1{}})
	ecdsa := mpc_ecdsa.NewECDSA(ecdsa_km, ecdsa_kr, vss_km, vss_kr)

	ec_vss_kr := inmem_keyrepo.NewKeyRepository()
	ec_vss_km := mpc_ecdsa.NewECDSA(ecdsa_km, ec_vss_kr, nil, nil)

	rid_kr := inmem_keyrepo.NewKeyRepository()
	rid_ks := keystore.NewInMemoryKeystore()
	rid_km := sw_rid.NewRIDManager(rid_ks)
	rid := mpc_rid.NewRIDKeyManager(rid_km, rid_kr)

	chainKey_kr := inmem_keyrepo.NewKeyRepository()
	chainKey_ks := keystore.NewInMemoryKeystore()
	chainKey_km := sw_rid.NewRIDManager(chainKey_ks)
	chainKey := mpc_rid.NewRIDKeyManager(chainKey_km, chainKey_kr)

	hash_ks := keystore.NewInMemoryKeystore()
	hash_mgr := sw_hash.NewHashManager(hash_ks)

	commitstore := inmem_commitstore.NewInMemoryCommitstore()
	commit_kr := inmem_keyrepo.NewKeyRepository()
	commit_mgr := commitment.NewCommitmentManager(commitstore, commit_kr)

	return NewMPCKeygen(
		elgamal,
		paillier,
		pedersen,
		ecdsa,
		ec_vss_km,
		rid,
		chainKey,
		hash_mgr,
		mpc_ks,
		commit_mgr,
		pl,
	)
}

func TestKeygen(t *testing.T) {
	keyID := uuid.NewString()

	pl := pool.NewPool(0)
	defer pl.TearDown()

	N := 3
	partyIDs := test.PartyIDs(N)

	rounds := make([]round.Session, 0, N)
	for _, partyID := range partyIDs {
		info := round.Info{
			ProtocolID:       "cmp/keygen-test",
			FinalRoundNumber: Rounds,
			SelfID:           partyID,
			PartyIDs:         partyIDs,
			Threshold:        N - 1,
			Group:            group,
		}
		mpckg := newMPCKeygen()
		r, err := mpckg.Start(keyID, info, pl, nil)(nil)
		fmt.Printf("r: %v\n", r)
		require.NoError(t, err, "round creation should not result in an error")
		rounds = append(rounds, r)
	}

	for {
		err, done := test.Rounds(rounds, nil)
		require.NoError(t, err, "failed to process round")
		if done {
			break
		}
	}
	// checkOutput(t, rounds)
}

func TestRefresh(t *testing.T) {
	keyID := uuid.NewString()

	pl := pool.NewPool(0)
	defer pl.TearDown()

	N := 4
	T := N - 1
	configs, _ := test.GenerateConfig(group, N, T, mrand.New(mrand.NewSource(1)), pl)

	rounds := make([]round.Session, 0, N)
	for _, c := range configs {
		info := round.Info{
			ProtocolID:       "cmp/refresh-test",
			FinalRoundNumber: Rounds,
			SelfID:           c.ID,
			PartyIDs:         c.PartyIDs(),
			Threshold:        N - 1,
			Group:            group,
		}
		mpckg := newMPCKeygen()
		r, err := mpckg.Start(keyID, info, pl, c)(nil)
		require.NoError(t, err, "round creation should not result in an error")
		rounds = append(rounds, r)
	}

	for {
		err, done := test.Rounds(rounds, nil)
		require.NoError(t, err, "failed to process round")
		if done {
			break
		}
	}
	checkOutput(t, rounds)
}
