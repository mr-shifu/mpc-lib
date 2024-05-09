package sign

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/party"
	"github.com/mr-shifu/mpc-lib/core/pool"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/lib/test"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/commitment"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/rid"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/config"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/message"
	edsig "github.com/mr-shifu/mpc-lib/pkg/mpc/result/eddsa"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/state"
	"github.com/mr-shifu/mpc-lib/pkg/vault"
	"github.com/mr-shifu/mpc-lib/protocols/frost/keygen"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func newFROSTMPC() (*keygen.FROSTKeygen, *FROSTSign) {
	pl := pool.NewPool(0)

	keycfgstore := config.NewInMemoryConfigStore()
	keycfgmr := config.NewKeyConfigManager(keycfgstore)

	keystatestore := state.NewInMemoryStateStore()
	signstatestore := state.NewInMemoryStateStore()
	keystatemgr := state.NewMPCStateManager(keystatestore)
	signstatemgr := state.NewMPCStateManager(signstatestore)

	msgstore := message.NewInMemoryMessageStore()
	bcststore := message.NewInMemoryMessageStore()
	msgmgr := message.NewMessageManager(msgstore)
	bcstmgr := message.NewMessageManager(bcststore)

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

	chainKey_keyopts := keyopts.NewInMemoryKeyOpts()
	chainKey_vault := vault.NewInMemoryVault()
	chainKey_ks := keystore.NewInMemoryKeystore(chainKey_vault, chainKey_keyopts)
	chainKey_km := rid.NewRIDManager(chainKey_ks)

	hahs_keyopts := keyopts.NewInMemoryKeyOpts()
	hahs_vault := vault.NewInMemoryVault()
	hash_ks := keystore.NewInMemoryKeystore(hahs_vault, hahs_keyopts)
	hash_mgr := hash.NewHashManager(hash_ks)

	commit_keyopts := keyopts.NewInMemoryKeyOpts()
	commit_vault := vault.NewInMemoryVault()
	commit_ks := keystore.NewInMemoryKeystore(commit_vault, commit_keyopts)
	commit_mgr := commitment.NewCommitmentManager(commit_ks)

	cfgstore := config.NewInMemoryConfigStore()
	signcfgmgr := config.NewSignConfigManager(cfgstore)

	edsig_keyopts := keyopts.NewInMemoryKeyOpts()
	edsigstore := edsig.NewInMemoryEddsaSignature(edsig_keyopts)
	edsigmgr := edsig.NewEddsaSignatureManager(edsigstore)

	ec_sign_keyopts := keyopts.NewInMemoryKeyOpts()
	ec_sign_ks := keystore.NewInMemoryKeystore(ec_vault, ec_sign_keyopts)
	ec_sign_km := ecdsa.NewECDSAKeyManager(ec_sign_ks, sch_ks, vss_km, &ecdsa.Config{Group: curve.Secp256k1{}})

	sign_d_keyopts := keyopts.NewInMemoryKeyOpts()
	sign_d_ks := keystore.NewInMemoryKeystore(ec_vault, sign_d_keyopts)
	sign_d_km := ecdsa.NewECDSAKeyManager(sign_d_ks, sch_ks, vss_km, &ecdsa.Config{Group: curve.Secp256k1{}})

	sign_e_keyopts := keyopts.NewInMemoryKeyOpts()
	sign_e_ks := keystore.NewInMemoryKeystore(ec_vault, sign_e_keyopts)
	sign_e_km := ecdsa.NewECDSAKeyManager(sign_e_ks, sch_ks, vss_km, &ecdsa.Config{Group: curve.Secp256k1{}})

	keygenmgr := keygen.NewFROSTKeygen(
		keycfgmr,
		keystatemgr,
		msgmgr,
		bcstmgr,
		ecdsa_km,
		ec_vss_km,
		vss_km,
		chainKey_km,
		hash_mgr,
		commit_mgr,
		pl,
	)

	signmanager := NewFROSTSign(
		signcfgmgr,
		signstatemgr,
		edsigmgr,
		msgmgr,
		bcstmgr,
		ecdsa_km,
		ec_vss_km,
		ec_sign_km,
		vss_km,
		sign_d_km,
		sign_e_km,
		hash_mgr,
	)

	return keygenmgr, signmanager
}

func TestSign(t *testing.T) {
	keyID := uuid.NewString()

	pl := pool.NewPool(0)
	defer pl.TearDown()

	var group = curve.Secp256k1{}

	N := 2
	partyIDs := test.PartyIDs(N)

	mpckeygens := make(map[party.ID]*keygen.FROSTKeygen)
	mpcsigns := make(map[party.ID]*FROSTSign)

	for _, partyID := range partyIDs {
		mpckg, mpcSign := newFROSTMPC()
		mpckeygens[partyID] = mpckg
		mpcsigns[partyID] = mpcSign
	}

	rounds := make([]round.Session, 0, N)
	for _, partyID := range partyIDs {
		keycfg := config.NewKeyConfig(keyID, group, N-1, partyID, partyIDs)

		mpckg := mpckeygens[partyID]

		r, err := mpckg.Start(keycfg, pl)(nil)
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

	signID := uuid.NewString()

	messageToSign := []byte("hello")
	messageHash := make([]byte, 64)
	sha3.ShakeSum128(messageHash, messageToSign)

	signRounds := make([]round.Session, 0, N)
	for _, partyID := range partyIDs {
		cfg := config.NewSignConfig(signID, keyID, group, N-1, partyID, partyIDs, messageHash)

		mpcsign := mpcsigns[partyID]

		r, err := mpcsign.Start(cfg, pl)(nil)
		fmt.Printf("r: %v\n", r)
		require.NoError(t, err, "round creation should not result in an error")
		signRounds = append(signRounds, r)
	}

	for {
		err, done := test.Rounds(signRounds, nil)
		require.NoError(t, err, "failed to process round")
		if done {
			break
		}
	}

	// rounds := make([]round.Session, 0, N)
	// for _, partyID := range partyIDs {
	// 	cfg := config.NewKeyConfig(keyID, group, N-1, partyID, partyIDs)
	// 	mpckg, mpcsign := newFROSTMPC()
	// 	r, err := mpckg.Start(cfg, pl)(nil)
	// 	fmt.Printf("r: %v\n", r)
	// 	require.NoError(t, err, "round creation should not result in an error")
	// 	rounds = append(rounds, r)
	// }

	// for {
	// 	err, done := test.Rounds(rounds, nil)
	// 	require.NoError(t, err, "failed to process round")
	// 	if done {
	// 		break
	// 	}
	// }

	// for _, partyID := range partyIDs {
	// 	cfg := config.NewKeyConfig(keyID, group, N-1, partyID, partyIDs)
	// 	mpckg, mpcsign := newFROSTMPC()
	// 	r, err := mpckg.Start(cfg, pl)(nil)
	// 	fmt.Printf("r: %v\n", r)
	// 	require.NoError(t, err, "round creation should not result in an error")
	// 	rounds = append(rounds, r)
	// }

	// for {
	// 	err, done := test.Rounds(rounds, nil)
	// 	require.NoError(t, err, "failed to process round")
	// 	if done {
	// 		break
	// 	}
	// }
}
