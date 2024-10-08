package keygen

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/pool"
	"github.com/mr-shifu/mpc-lib/core/protocol"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/lib/test"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/commitment"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/elgamal"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillier"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/pedersen"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/rid"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/config"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/message"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/state"
	"github.com/mr-shifu/mpc-lib/pkg/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var group = curve.Secp256k1{}

func checkOutput(t *testing.T, rounds []round.Session) {
	N := len(rounds)
	newConfigs := make([]*Config, 0, N)
	for _, r := range rounds {
		require.IsType(t, &round.Output{}, r)
		resultRound := r.(*round.Output)
		require.IsType(t, &Config{}, resultRound.Result)
		c := resultRound.Result.(*Config)
		newConfigs = append(newConfigs, c)
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
	}
}

func newMPCKeygen() *MPCKeygen {
	pl := pool.NewPool(0)

	keycfgstore := config.NewInMemoryConfigStore()
	keycfgmr := config.NewKeyConfigManager(keycfgstore)

	keystatestore := state.NewInMemoryStateStore()
	keystatemgr := state.NewMPCStateManager(keystatestore)

	msgstore := message.NewInMemoryMessageStore()
	bcststore := message.NewInMemoryMessageStore()
	msgmgr := message.NewMessageManager(msgstore)
	bcstmgr := message.NewMessageManager(bcststore)

	elgamal_keyopts := keyopts.NewInMemoryKeyOpts()
	elgamal_vault := vault.NewInMemoryVault()
	elgamal_ks := keystore.NewInMemoryKeystore(elgamal_vault, elgamal_keyopts)
	elgamal_km := elgamal.NewElgamalKeyManager(elgamal_ks, &elgamal.Config{Group: curve.Secp256k1{}})

	paillier_keyopts := keyopts.NewInMemoryKeyOpts()
	paillier_vault := vault.NewInMemoryVault()
	paillier_ks := keystore.NewInMemoryKeystore(paillier_vault, paillier_keyopts)
	paillier_km := paillier.NewPaillierKeyManager(paillier_ks, pl)

	pedersen_keyopts := keyopts.NewInMemoryKeyOpts()
	pedersen_vault := vault.NewInMemoryVault()
	pedersen_ks := keystore.NewInMemoryKeystore(pedersen_vault, pedersen_keyopts)
	pedersen_km := pedersen.NewPedersenKeymanager(pedersen_ks)

	vss_keyopts := keyopts.NewInMemoryKeyOpts()
	vss_vault := vault.NewInMemoryVault()
	vss_ks := keystore.NewInMemoryKeystore(vss_vault, vss_keyopts)
	vss_km := vss.NewVssKeyManager(vss_ks, curve.Secp256k1{})

	ec_keyopts := keyopts.NewInMemoryKeyOpts()
	ec_vault := vault.NewInMemoryVault()
	ec_ks := keystore.NewInMemoryKeystore(ec_vault, ec_keyopts)
	sch_keyopts := keyopts.NewInMemoryKeyOpts()
	sch_vault := vault.NewInMemoryVault()
	sch_ks := keystore.NewInMemoryKeystore(sch_vault, sch_keyopts)
	ecdsa_km := ecdsa.NewECDSAKeyManager(ec_ks, sch_ks, vss_km, &ecdsa.Config{Group: curve.Secp256k1{}})

	ec_vss_keyopts := keyopts.NewInMemoryKeyOpts()
	ec_vss_ks := keystore.NewInMemoryKeystore(ec_vault, ec_vss_keyopts)
	ec_vss_km := ecdsa.NewECDSAKeyManager(ec_vss_ks, sch_ks, vss_km, &ecdsa.Config{Group: curve.Secp256k1{}})

	rid_keyopts := keyopts.NewInMemoryKeyOpts()
	rid_vault := vault.NewInMemoryVault()
	rid_ks := keystore.NewInMemoryKeystore(rid_vault, rid_keyopts)
	rid_km := rid.NewRIDManagerImpl(rid_ks)

	chainKey_keyopts := keyopts.NewInMemoryKeyOpts()
	chainKey_vault := vault.NewInMemoryVault()
	chainKey_ks := keystore.NewInMemoryKeystore(chainKey_vault, chainKey_keyopts)
	chainKey_km := rid.NewRIDManagerImpl(chainKey_ks)

	hahs_keyopts := keyopts.NewInMemoryKeyOpts()
	hahs_vault := vault.NewInMemoryVault()
	hash_ks := keystore.NewInMemoryKeystore(hahs_vault, hahs_keyopts)
	hash_mgr := hash.NewHashManager(hash_ks)

	commit_keyopts := keyopts.NewInMemoryKeyOpts()
	commit_vault := vault.NewInMemoryVault()
	commit_ks := keystore.NewInMemoryKeystore(commit_vault, commit_keyopts)
	commit_mgr := commitment.NewCommitmentManagerImpl(commit_ks)

	return NewMPCKeygen(
		keycfgmr,
		keystatemgr,
		msgmgr,
		bcstmgr,
		elgamal_km,
		paillier_km,
		pedersen_km,
		ecdsa_km,
		ec_vss_km,
		vss_km,
		rid_km,
		chainKey_km,
		hash_mgr,
		commit_mgr,
		pl,
	)
}

func TestKeygen(t *testing.T) {
	keyID := uuid.NewString()

	pl := pool.NewPool(0)
	defer pl.TearDown()

	var group = curve.Secp256k1{}

	N := 3
	partyIDs := test.PartyIDs(N)

	kgs := make([]protocol.Processor, 0, N)
	for _, partyID := range partyIDs {
		cfg := config.NewKeyConfig(keyID, group, N-1, partyID, partyIDs)
		mpckg := newMPCKeygen()
		kgs = append(kgs, mpckg)
		_, err := mpckg.Start(cfg)(nil)
		require.NoError(t, err, "round creation should not result in an error")
	}

	for {
		rounds, done, err := test.CMPRounds(kgs, keyID)
		require.NoError(t, err, "failed to process round")
		if done {
			for _, r := range rounds {
				r, ok := r.(*round.Output)
				if ok {
					res, ok := r.Result.(*Result)
					assert.True(t, ok)
					kb, err := res.PublicKey.MarshalBinary()
					kb64 := hex.EncodeToString(kb)
					assert.NoError(t, err)
					fmt.Printf("Public Key: %s\n", kb64)
				}
			}
			break
		}
	}
}
