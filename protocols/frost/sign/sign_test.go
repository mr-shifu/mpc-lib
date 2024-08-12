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
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/commitment"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ed25519"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/rid"
	vssed25519 "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss-ed25519"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/result"
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
	vss_km := vssed25519.NewVssKeyManager(vss_ks)

	ed_keyopts := keyopts.NewInMemoryKeyOpts()
	ed_vault := vault.NewInMemoryVault()
	ed_ks := keystore.NewInMemoryKeystore(ed_vault, ed_keyopts)
	sch_keyopts := keyopts.NewInMemoryKeyOpts()
	sch_vault := vault.NewInMemoryVault()
	sch_ks := keystore.NewInMemoryKeystore(sch_vault, sch_keyopts)
	ecdsa_km := ed25519.NewEd25519KeyManagerImpl(ed_ks, sch_ks, vss_km)

	ed_vss_keyopts := keyopts.NewInMemoryKeyOpts()
	ed_vss_ks := keystore.NewInMemoryKeystore(ed_vault, ed_vss_keyopts)
	ed_vss_km := ed25519.NewEd25519KeyManagerImpl(ed_vss_ks, sch_ks, vss_km)

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
	commit_mgr := commitment.NewCommitmentManagerImpl(commit_ks)

	cfgstore := config.NewInMemoryConfigStore()
	signcfgmgr := config.NewSignConfigManager(cfgstore)

	edsig_keyopts := keyopts.NewInMemoryKeyOpts()
	edsigstore := edsig.NewInMemoryEddsaSignature(edsig_keyopts)
	edsigmgr := edsig.NewEddsaSignatureManager(edsigstore)

	ed_sign_keyopts := keyopts.NewInMemoryKeyOpts()
	ed_sign_ks := keystore.NewInMemoryKeystore(ed_vault, ed_sign_keyopts)
	ed_sign_km := ed25519.NewEd25519KeyManagerImpl(ed_sign_ks, sch_ks, vss_km)

	sign_d_keyopts := keyopts.NewInMemoryKeyOpts()
	sign_d_ks := keystore.NewInMemoryKeystore(ed_vault, sign_d_keyopts)
	sign_d_km := ed25519.NewEd25519KeyManagerImpl(sign_d_ks, sch_ks, vss_km)

	sign_e_keyopts := keyopts.NewInMemoryKeyOpts()
	sign_e_ks := keystore.NewInMemoryKeystore(ed_vault, sign_e_keyopts)
	sign_e_km := ed25519.NewEd25519KeyManagerImpl(sign_e_ks, sch_ks, vss_km)

	keygenmgr := keygen.NewFROSTKeygen(
		keycfgmr,
		keystatemgr,
		msgmgr,
		bcstmgr,
		ecdsa_km,
		ed_vss_km,
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
		ed_vss_km,
		ed_sign_km,
		vss_km,
		sign_d_km,
		sign_e_km,
		hash_mgr,
		pl,
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

	mpckeygens := make([]protocol.Processor, 0, N)
	mpcsigns := make([]protocol.Processor, 0, N)
	for range partyIDs {
		mpckg, mpcSign := newFROSTMPC()
		mpckeygens = append(mpckeygens, mpckg)
		mpcsigns = append(mpcsigns, mpcSign)
	}

	keycfgs := make([]*config.KeyConfig, 0, N)
	for i, partyID := range partyIDs {
		mpckg := mpckeygens[i]
		keycfg := config.NewKeyConfig(keyID, group, N-1, partyID, partyIDs)
		keycfgs = append(keycfgs, keycfg)

		_, err := mpckg.Start(keycfg)(nil)
		require.NoError(t, err, "round creation should not result in an error")
	}

	for {
		rounds, done, err := test.FROSTRounds(mpckeygens, keyID)
		require.NoError(t, err, "failed to process round")
		if done {
			for _, r := range rounds {
				r, ok := r.(*round.Output)
				if ok {
					res := r.Result.(*keygen.Config)
					fmt.Printf("[Party %s]Output PublicKey: %x\n", r.SelfID(), res.PublicKey.Bytes())
				}
			}
			break
		}
	}

	for i, kg := range mpckeygens {
		_, err := kg.Start(keycfgs[i])(nil)
		require.NoError(t, err, "round creation should not result in an error")
	}

	for {
		rounds, done, err := test.FROSTRounds(mpckeygens, keyID)
		require.NoError(t, err, "failed to process round")
		if done {
			for _, r := range rounds {
				r, ok := r.(*round.Output)
				if ok {
					res := r.Result.(*keygen.Config)
					fmt.Printf("Output: %x\n", res.PublicKey.Bytes())
				}
			}
			break
		}
	}

	signID := uuid.NewString()

	messageToSign := []byte("hello")
	messageHash := make([]byte, 64)
	sha3.ShakeSum128(messageHash, messageToSign)

	for i, partyID := range partyIDs {
		cfg := config.NewSignConfig(signID, keyID, group, N-1, partyID, partyIDs, messageHash)

		mpcsign := mpcsigns[i]

		_, err := mpcsign.Start(cfg)(nil)
		require.NoError(t, err, "round creation should not result in an error")
	}

	for {
		rounds, done, err := test.FROSTRounds(mpcsigns, signID)
		require.NoError(t, err, "failed to process round")
		if done {
			for _, r := range rounds {
				r, ok := r.(*round.Output)
				if ok {
					res := r.Result.(result.EddsaSignature)
					// sig := make([]byte, 0)
					sig := append(res.R().Bytes(), res.Z().Bytes()...)
					fmt.Printf("[Party %s]Output Signature: %x\n", r.SelfID(), sig)
				}
			}
			break
		}
	}
}
