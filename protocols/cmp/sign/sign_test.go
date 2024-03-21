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
	"github.com/mr-shifu/mpc-lib/pkg/commitstore"
	"github.com/mr-shifu/mpc-lib/pkg/keyrepository"
	"github.com/mr-shifu/mpc-lib/pkg/keystore"
	"github.com/mr-shifu/mpc-lib/protocols/cmp/keygen"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	sw_elgamal "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/elgamal"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/commitment"
	mpc_elgamal "github.com/mr-shifu/mpc-lib/pkg/mpc/elgamal"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/mpckey"

	sw_paillier "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillier"
	mpc_paillier "github.com/mr-shifu/mpc-lib/pkg/mpc/paillier"

	sw_mta "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/mta"
	sw_pek "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillierencodedkey"

	sw_pedersen "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/pedersen"
	mpc_pedersen "github.com/mr-shifu/mpc-lib/pkg/mpc/pedersen"

	sw_rid "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/rid"
	mpc_rid "github.com/mr-shifu/mpc-lib/pkg/mpc/rid"

	sw_vss "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss"

	sw_ecdsa "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ecdsa"
	mpc_ecdsa "github.com/mr-shifu/mpc-lib/pkg/mpc/ecdsa"

	sw_hash "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"

	mpc_config "github.com/mr-shifu/mpc-lib/pkg/mpc/config"
	mpc_mta "github.com/mr-shifu/mpc-lib/pkg/mpc/mta"
	mpc_pek "github.com/mr-shifu/mpc-lib/pkg/mpc/pekmanager"
	mpc_result "github.com/mr-shifu/mpc-lib/pkg/mpc/result"
)

func newMPC() (*keygen.MPCKeygen, *MPCSign) {
	pl := pool.NewPool(0)

	mpc_ks := mpckey.NewInMemoryMPCKeystore()

	ksf := keystore.InmemoryKeystoreFactory{}
	krf := keyrepository.InMemoryKeyRepositoryFactory{}

	elgamal_kr := krf.NewKeyRepository(nil)
	elgamal_ks := ksf.NewKeystore(nil)
	elgamal_km := sw_elgamal.NewElgamalKeyManager(elgamal_ks, &sw_elgamal.Config{Group: curve.Secp256k1{}})
	elgamal := mpc_elgamal.NewElgamal(elgamal_km, elgamal_kr)

	paillier_kr := krf.NewKeyRepository(nil)
	paillier_ks := ksf.NewKeystore(nil)
	paillier_km := sw_paillier.NewPaillierKeyManager(paillier_ks, pl)
	paillier := mpc_paillier.NewPaillierKeyManager(paillier_km, paillier_kr)

	pedersen_kr := krf.NewKeyRepository(nil)
	pedersen_ks := ksf.NewKeystore(nil)
	pedersen_km := sw_pedersen.NewPedersenKeymanager(pedersen_ks)
	pedersen := mpc_pedersen.NewPedersenKeyManager(pedersen_km, pedersen_kr)

	vss_kr := krf.NewKeyRepository(nil)
	vss_ks := ksf.NewKeystore(nil)
	vss_ss := sw_vss.NewInMemoryVSSShareStore()
	vss_km := sw_vss.NewVssKeyManager(vss_ks, vss_ss, curve.Secp256k1{})

	pek_ks := ksf.NewKeystore(nil)
	pek_mgr := sw_pek.NewPaillierEncodedKeyManager(pek_ks)


	ecdsa_ks := ksf.NewKeystore(nil)
	ecdsa_kr := krf.NewKeyRepository(nil)
	sch_ks := ksf.NewKeystore(nil)
	ecdsa_km := sw_ecdsa.NewECDSAKeyManager(ecdsa_ks, sch_ks, vss_km, &sw_ecdsa.Config{Group: curve.Secp256k1{}})
	ecdsa := mpc_ecdsa.NewECDSA(ecdsa_km, ecdsa_kr, vss_km, vss_kr)

	rid_kr := krf.NewKeyRepository(nil)
	rid_ks := ksf.NewKeystore(nil)
	rid_km := sw_rid.NewRIDManager(rid_ks)
	rid := mpc_rid.NewRIDKeyManager(rid_km, rid_kr)

	chainKey_kr := krf.NewKeyRepository(nil)
	chainKey_ks := ksf.NewKeystore(nil)
	chainKey_km := sw_rid.NewRIDManager(chainKey_ks)
	chainKey := mpc_rid.NewRIDKeyManager(chainKey_km, chainKey_kr)

	hash_ks := ksf.NewKeystore(nil)
	hash_mgr := sw_hash.NewHashManager(hash_ks)

	commitstore := commitstore.NewInMemoryCommitstore()
	commit_kr := krf.NewKeyRepository(nil)
	commit_mgr := commitment.NewCommitmentManager(commitstore, commit_kr)

	mpc_keygen := keygen.NewMPCKeygen(
		elgamal,
		paillier,
		pedersen,
		ecdsa,
		rid,
		chainKey,
		hash_mgr,
		mpc_ks,
		commit_mgr,
		pl,
	)

	sigma_kr := krf.NewKeyRepository(nil)
	sigma_ks := ksf.NewKeystore(nil)
	sigma := mpc_result.NewSigmaStore(sigma_ks, sigma_kr)

	sign_cfg := mpc_config.NewSignConfigManager()

	signature := mpc_result.NewSignStore()

	gamma_kr := krf.NewKeyRepository(nil)
	gamma_mgr := mpc_ecdsa.NewECDSA(ecdsa_km, gamma_kr, nil, nil)

	signK_kr := krf.NewKeyRepository(nil)
	signK_mgr := mpc_ecdsa.NewECDSA(ecdsa_km, signK_kr, nil, nil)

	delta_kr := krf.NewKeyRepository(nil)
	delta_mgr := mpc_ecdsa.NewECDSA(ecdsa_km, delta_kr, nil, nil)

	chi_kr := krf.NewKeyRepository(nil)
	chi_mgr := mpc_ecdsa.NewECDSA(ecdsa_km, chi_kr, nil, nil)

	bigDelta_kr := krf.NewKeyRepository(nil)
	bigDelta_mgr := mpc_ecdsa.NewECDSA(ecdsa_km, bigDelta_kr, nil, nil)

	gamma_pek_kr := krf.NewKeyRepository(nil)
	gamma_pek := mpc_pek.NewPaillierKeyManager(pek_mgr, gamma_pek_kr)

	signK_pek_kr := krf.NewKeyRepository(nil)
	signK_pek := mpc_pek.NewPaillierKeyManager(pek_mgr, signK_pek_kr)

	delta_mta_kr := krf.NewKeyRepository(nil)
	mta_ks := ksf.NewKeystore(nil)
	mta_km := sw_mta.NewMtAManager(mta_ks)
	delta_mta := mpc_mta.NewPaillierKeyManager(mta_km, delta_mta_kr)

	chi_mta_kr := krf.NewKeyRepository(nil)
	chi_mta := mpc_mta.NewPaillierKeyManager(mta_km, chi_mta_kr)

	mpc_sign := NewMPCSign(
		sign_cfg,
		hash_mgr,
		paillier,
		pedersen,
		ecdsa,
		gamma_mgr,
		signK_mgr,
		delta_mgr,
		chi_mgr,
		bigDelta_mgr,
		gamma_pek,
		signK_pek,
		delta_mta,
		chi_mta,
		sigma,
		signature,
	)

	return mpc_keygen, mpc_sign
}

// func TestRound(t *testing.T) {
// 	pl := pool.NewPool(0)
// 	defer pl.TearDown()
// 	group := curve.Secp256k1{}

// 	N := 6
// 	T := N - 1

// 	t.Log("generating configs")
// 	configs, partyIDs := test.GenerateConfig(group, N, T, mrand.New(mrand.NewSource(1)), pl)
// 	t.Log("done generating configs")

// 	partyIDs = partyIDs[:T+1]
// 	publicPoint := configs[partyIDs[0]].PublicPoint()

// 	messageToSign := []byte("hello")
// 	messageHash := make([]byte, 64)
// 	sha3.ShakeSum128(messageHash, messageToSign)

// 	rounds := make([]round.Session, 0, N)
// 	for _, partyID := range partyIDs {
// 		c := configs[partyID]
// 		r, err := StartSign(c, partyIDs, messageHash, pl)(nil)
// 		require.NoError(t, err, "round creation should not result in an error")
// 		rounds = append(rounds, r)
// 	}

// 	for {
// 		err, done := test.Rounds(rounds, nil)
// 		require.NoError(t, err, "failed to process round")
// 		if done {
// 			break
// 		}
// 	}

// 	for _, r := range rounds {
// 		require.IsType(t, &round.Output{}, r, "expected result round")
// 		resultRound := r.(*round.Output)
// 		require.IsType(t, &ecdsa.Signature{}, resultRound.Result, "expected taproot signature result")
// 		signature := resultRound.Result.(*ecdsa.Signature)
// 		assert.True(t, signature.Verify(publicPoint, messageHash), "expected valid signature")
// 	}
// }

func TestSign(t *testing.T) {
	keyID := uuid.NewString()

	group := curve.Secp256k1{}

	KeygenRounds := round.Number(5)
	SignRounds := round.Number(5)

	pl := pool.NewPool(0)
	defer pl.TearDown()

	N := 2
	partyIDs := test.PartyIDs(N)

	mpckeygens := make(map[party.ID]*keygen.MPCKeygen)
	mpcsigns := make(map[party.ID]*MPCSign)

	for _, partyID := range partyIDs {
		mpckg, mpcSign := newMPC()
		mpckeygens[partyID] = mpckg
		mpcsigns[partyID] = mpcSign
	}

	rounds := make([]round.Session, 0, N)
	for _, partyID := range partyIDs {
		info := round.Info{
			ProtocolID:       "cmp/keygen-test",
			FinalRoundNumber: KeygenRounds,
			SelfID:           partyID,
			PartyIDs:         partyIDs,
			Threshold:        N - 1,
			Group:            group,
		}

		mpckg := mpckeygens[partyID]

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

	signID := uuid.NewString()

	messageToSign := []byte("hello")
	messageHash := make([]byte, 64)
	sha3.ShakeSum128(messageHash, messageToSign)

	signRounds := make([]round.Session, 0, N)
	for _, partyID := range partyIDs {
		info := round.Info{
			ProtocolID:       "cmp/sign-test",
			FinalRoundNumber: SignRounds,
			SelfID:           partyID,
			PartyIDs:         partyIDs,
			Threshold:        N - 1,
			Group:            group,
		}

		mpcsign := mpcsigns[partyID]

		r, err := mpcsign.StartSign(signID, keyID, info, partyIDs, messageHash, pl)(nil)
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
	// checkOutput(t, rounds)
}
