package sign

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/pool"
	"github.com/mr-shifu/mpc-lib/core/protocol"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/lib/test"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/vault"
	"github.com/mr-shifu/mpc-lib/protocols/cmp/keygen"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/commitment"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/elgamal"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	sw_mta "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/mta"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillier"
	pek "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillierencodedkey"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/pedersen"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/rid"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/config"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/message"
	ecsig "github.com/mr-shifu/mpc-lib/pkg/mpc/result/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/state"
)

func newMPC() (*keygen.MPCKeygen, *MPCSign) {
	pl := pool.NewPool(0)

	ecsig_keyopts := keyopts.NewInMemoryKeyOpts()
	ecsigstore := ecsig.NewInMemoryEcdsaSignature(ecsig_keyopts)
	ecsigmgr := ecsig.NewEcdsaSignatureManager(ecsigstore)

	ksf := keystore.InmemoryKeystoreFactory{}
	krf := keyopts.InMemoryKeyOptsFactory{}
	vf := vault.InmemoryVaultFactory{}
	keycfgstore := config.NewInMemoryConfigStore()
	signcfgstore := config.NewInMemoryConfigStore()

	keycfgmgr := config.NewKeyConfigManager(keycfgstore)
	signcfgmgr := config.NewSignConfigManager(signcfgstore)

	keystatestore := state.NewInMemoryStateStore()
	signstatestore := state.NewInMemoryStateStore()
	keystatemgr := state.NewMPCStateManager(keystatestore)
	signstatemgr := state.NewMPCStateManager(signstatestore)

	msgstore := message.NewInMemoryMessageStore()
	bcststore := message.NewInMemoryMessageStore()
	msgmgr := message.NewMessageManager(msgstore)
	bcstmgr := message.NewMessageManager(bcststore)

	elgamal_keyopts := krf.NewKeyOpts(nil)
	elgamal_vault := vf.NewVault(nil)
	elgamal_ks := ksf.NewKeystore(elgamal_vault, elgamal_keyopts, nil)
	elgamal_km := elgamal.NewElgamalKeyManager(elgamal_ks, &elgamal.Config{Group: curve.Secp256k1{}})

	paillier_keyopts := krf.NewKeyOpts(nil)
	paillier_vault := vf.NewVault(nil)
	paillier_ks := ksf.NewKeystore(paillier_vault, paillier_keyopts, nil)
	paillier_km := paillier.NewPaillierKeyManager(paillier_ks, pl)

	pedersen_keyopts := krf.NewKeyOpts(nil)
	pedersen_vault := vf.NewVault(nil)
	pedersen_ks := ksf.NewKeystore(pedersen_vault, pedersen_keyopts, nil)
	pedersen_km := pedersen.NewPedersenKeymanager(pedersen_ks)

	vss_keyopts := krf.NewKeyOpts(nil)
	vss_vault := vf.NewVault(nil)
	vss_ks := ksf.NewKeystore(vss_vault, vss_keyopts, nil)
	vss_km := vss.NewVssKeyManager(vss_ks, curve.Secp256k1{})

	ec_keyopts := krf.NewKeyOpts(nil)
	ec_vault := vf.NewVault(nil)
	ec_ks := ksf.NewKeystore(ec_vault, ec_keyopts, nil)
	sch_keyopts := krf.NewKeyOpts(nil)
	sch_vault := vf.NewVault(nil)
	sch_ks := ksf.NewKeystore(sch_vault, sch_keyopts, nil)
	ecdsa_km := ecdsa.NewECDSAKeyManager(ec_ks, sch_ks, vss_km, &ecdsa.Config{Group: curve.Secp256k1{}})

	ec_vss_keyopts := krf.NewKeyOpts(nil)
	ec_vss_ks := ksf.NewKeystore(ec_vault, ec_vss_keyopts, nil)
	ec_vss_km := ecdsa.NewECDSAKeyManager(ec_vss_ks, sch_ks, vss_km, &ecdsa.Config{Group: curve.Secp256k1{}})

	rid_keyopts := krf.NewKeyOpts(nil)
	rid_vault := vf.NewVault(nil)
	rid_ks := ksf.NewKeystore(rid_vault, rid_keyopts, nil)
	rid_km := rid.NewRIDManagerImpl(rid_ks)

	chainKey_keyopts := krf.NewKeyOpts(nil)
	chainKey_vault := vf.NewVault(nil)
	chainKey_ks := ksf.NewKeystore(chainKey_vault, chainKey_keyopts, nil)
	chainKey_km := rid.NewRIDManagerImpl(chainKey_ks)

	hahs_keyopts := krf.NewKeyOpts(nil)
	hahs_vault := vf.NewVault(nil)
	hash_ks := ksf.NewKeystore(hahs_vault, hahs_keyopts, nil)
	hash_mgr := hash.NewHashManager(hash_ks)

	commit_keyopts := keyopts.NewInMemoryKeyOpts()
	commit_vault := vault.NewInMemoryVault()
	commit_ks := keystore.NewInMemoryKeystore(commit_vault, commit_keyopts)
	commit_mgr := commitment.NewCommitmentManagerImpl(commit_ks)

	mpc_keygen := keygen.NewMPCKeygen(
		keycfgmgr,
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

	ec_sig_kr := krf.NewKeyOpts(nil)
	ec_sig_ks := ksf.NewKeystore(ec_vault, ec_sig_kr, nil)
	ec_sig_km := ecdsa.NewECDSAKeyManager(ec_sig_ks, sch_ks, vss_km, &ecdsa.Config{Group: curve.Secp256k1{}})

	
	gamma_kr := krf.NewKeyOpts(nil)
	gamma_ks := ksf.NewKeystore(ec_vault, gamma_kr, nil)
	gamma_km := ecdsa.NewECDSAKeyManager(gamma_ks, sch_ks, vss_km, &ecdsa.Config{Group: curve.Secp256k1{}})

	signK_kr := krf.NewKeyOpts(nil)
	signK_ks := ksf.NewKeystore(ec_vault, signK_kr, nil)
	signK_km := ecdsa.NewECDSAKeyManager(signK_ks, sch_ks, vss_km, &ecdsa.Config{Group: curve.Secp256k1{}})

	delta_kr := krf.NewKeyOpts(nil)
	delta_ks := ksf.NewKeystore(ec_vault, delta_kr, nil)
	delta_km := ecdsa.NewECDSAKeyManager(delta_ks, sch_ks, vss_km, &ecdsa.Config{Group: curve.Secp256k1{}})

	chi_kr := krf.NewKeyOpts(nil)
	chi_ks := ksf.NewKeystore(ec_vault, chi_kr, nil)
	chi_km := ecdsa.NewECDSAKeyManager(chi_ks, sch_ks, vss_km, &ecdsa.Config{Group: curve.Secp256k1{}})

	bigDelta_kr := krf.NewKeyOpts(nil)
	bigDelta_ks := ksf.NewKeystore(ec_vault, bigDelta_kr, nil)
	bigDelta_km := ecdsa.NewECDSAKeyManager(bigDelta_ks, sch_ks, vss_km, &ecdsa.Config{Group: curve.Secp256k1{}})

	gamma_pek_vault := vf.NewVault(nil)
	gamma_pek_kr := krf.NewKeyOpts(nil)
	gamma_pek_ks := ksf.NewKeystore(gamma_pek_vault, gamma_pek_kr, nil)
	gamma_pek_mgr := pek.NewPaillierEncodedKeyManager(gamma_pek_ks)

	signK_pek_vault := vf.NewVault(nil)
	signK_pek_kr := krf.NewKeyOpts(nil)
	signK_pek_ks := ksf.NewKeystore(signK_pek_vault, signK_pek_kr, nil)
	signK_pek_mgr := pek.NewPaillierEncodedKeyManager(signK_pek_ks)

	delta_mta_vault := vf.NewVault(nil)
	delta_mta_kr := krf.NewKeyOpts(nil)
	delta_mta_ks := ksf.NewKeystore(delta_mta_vault, delta_mta_kr, nil)
	delta_mta_km := sw_mta.NewMtAManager(delta_mta_ks)

	chi_mta_vault := vf.NewVault(nil)
	chi_mta_kr := krf.NewKeyOpts(nil)
	chi_mta_ks := ksf.NewKeystore(chi_mta_vault, chi_mta_kr, nil)
	chi_mta_km := sw_mta.NewMtAManager(chi_mta_ks)

	mpc_sign := NewMPCSign(
		signcfgmgr,
		signstatemgr,
		msgmgr,
		bcstmgr,
		hash_mgr,
		paillier_km,
		pedersen_km,
		ecdsa_km,
		ec_sig_km,
		ec_vss_km,
		vss_km,
		gamma_km,
		signK_km,
		delta_km,
		chi_km,
		bigDelta_km,
		gamma_pek_mgr,
		signK_pek_mgr,
		delta_mta_km,
		chi_mta_km,
		ecsigmgr,
		pl,
	)

	return mpc_keygen, mpc_sign
}

func TestSign(t *testing.T) {
	keyID := uuid.NewString()

	pl := pool.NewPool(0)
	defer pl.TearDown()

	var group = curve.Secp256k1{}

	N := 2
	partyIDs := test.PartyIDs(N)

	mpckeygens := make([]protocol.Processor, 0, N)
	mpcsigns := make([]protocol.Processor, 0, N)
	for range partyIDs {
		mpckg, mpcSign := newMPC()
		mpckeygens = append(mpckeygens, mpckg)
		mpcsigns = append(mpcsigns, mpcSign)
	}

	for i, partyID := range partyIDs {
		mpckg := mpckeygens[i]
		keycfg := config.NewKeyConfig(keyID, group, N-1, partyID, partyIDs)
		_, err := mpckg.Start(keycfg)(nil)
		require.NoError(t, err, "round creation should not result in an error")
	}

	for {
		_, done, err := test.CMPRounds(mpckeygens, keyID)
		require.NoError(t, err, "failed to process round")
		if done {
			break
		}
	}

	signID := uuid.NewString()

	messageToSign := []byte("hello")
	messageHash := make([]byte, 64)
	sha3.ShakeSum128(messageHash, messageToSign)

	for i, partyID := range partyIDs {
		cfg := config.NewSignConfig(signID, keyID, partyID, partyIDs, messageHash)

		mpcsign := mpcsigns[i]

		_, err := mpcsign.Start(cfg)(nil)
		require.NoError(t, err, "round creation should not result in an error")
	}

	for {
		rounds, done, err := test.CMPRounds(mpcsigns, signID)
		require.NoError(t, err, "failed to process round")
		if done {
			for _, r := range rounds {
				r, ok := r.(*round.Output)
				if ok {
					res := r.Result.(*ecsig.EcdsaSignature)
					rb, _ := res.SignR().MarshalBinary()
					sb, _ := res.SignSigma().MarshalBinary()
					sig := append(rb, sb...)
					fmt.Printf("[Party %s]Output Signature: %x\n", r.SelfID(), sig)
				}
			}
			break
		}
	}
}
