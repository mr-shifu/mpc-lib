package sign

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/party"
	"github.com/mr-shifu/mpc-lib/core/pool"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/lib/test"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/commitment"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ed25519"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/rid"
	vssed25519 "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss-ed25519"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/config"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/message"
	edsig "github.com/mr-shifu/mpc-lib/pkg/mpc/result/eddsa"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/state"
	"github.com/mr-shifu/mpc-lib/pkg/vault"
	"github.com/mr-shifu/mpc-lib/protocols/frost/keygen"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
	"golang.org/x/sync/errgroup"
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
	commit_mgr := commitment.NewCommitmentManager(commit_ks)

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

		r, err := mpckg.Start(keycfg)(nil)
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

		r, err := mpcsign.Start(cfg)(nil)
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
}

func testRounds(kgs []*FROSTSign, keyID string) (error, bool) {
	var (
		err       error
		roundType reflect.Type
		errGroup  errgroup.Group
		N         = len(kgs)
		out       = make(chan *round.Message, N*(N+1))
	)

	rounds := make([]round.Session, N)
	for id := range kgs {
		idx := id
		kg := kgs[idx]
		r, err := kg.GetRound(keyID)
		if err != nil {
			return err, false
		}
		rounds[idx] = r
	}
	if _, err = checkAllRoundsSame(rounds); err != nil {
		return err, false
	}

	// get the second set of messages
	for id := range kgs {
		idx := id
		kg := kgs[idx]
		errGroup.Go(func() error {
			// var rNew round.Session
			rNew, err := kg.Finalize(out, keyID)

			if err != nil {
				return err
			}

			if rNew != nil {
				rounds[idx] = rNew
			}
			return nil
		})
	}
	if err = errGroup.Wait(); err != nil {
		return err, false
	}
	close(out)

	// Check that all rounds are the same type
	if roundType, err = checkAllRoundsSame(rounds); err != nil {
		return err, false
	}
	if roundType.String() == reflect.TypeOf(&round.Output{}).String() {
		return nil, true
	}
	if roundType.String() == reflect.TypeOf(&round.Abort{}).String() {
		return nil, true
	}

	for msg := range out {
		fmt.Printf("Party msg: %v\n", msg)
		msgBytes, err := cbor.Marshal(msg.Content)
		if err != nil {
			return err, false
		}
		for _, kg := range kgs {
			kg := kg
			r, err := kg.GetRound(keyID)
			if err != nil {
				return err, false
			}
			m := *msg
			if msg.From == r.SelfID() || msg.Content.RoundNumber() != r.Number() {
				continue
			}
			errGroup.Go(func() error {
				if m.Broadcast {
					b, ok := r.(round.BroadcastRound)
					if !ok {
						return errors.New("broadcast message but not broadcast round")
					}
					m.Content = b.BroadcastContent()
					if err = cbor.Unmarshal(msgBytes, m.Content); err != nil {
						return err
					}

					if err = b.StoreBroadcastMessage(m); err != nil {
						return err
					}
				} else {
					m.Content = r.MessageContent()
					if err = cbor.Unmarshal(msgBytes, m.Content); err != nil {
						return err
					}

					if m.To == "" || m.To == r.SelfID() {
						if err = r.VerifyMessage(m); err != nil {
							return err
						}
						if err = r.StoreMessage(m); err != nil {
							return err
						}
					}
				}

				return nil
			})
		}
		if err = errGroup.Wait(); err != nil {
			return err, false
		}
	}

	return nil, false
}

func checkAllRoundsSame(rounds []round.Session) (reflect.Type, error) {
	var t reflect.Type
	for _, r := range rounds {
		rReal := getRound(r)
		t2 := reflect.TypeOf(rReal)
		if t == nil {
			t = t2
		} else if t != t2 {
			return t, fmt.Errorf("two different rounds: %s %s", t, t2)
		}
	}
	return t, nil
}

func getRound(outerRound round.Session) round.Session {
	return outerRound
}
