package keygen

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/fxamacker/cbor/v2"
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
	"github.com/mr-shifu/mpc-lib/pkg/mpc/config"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/message"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/state"
	"github.com/mr-shifu/mpc-lib/pkg/vault"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func newFROSTKeygen() *FROSTKeygen {
	pl := pool.NewPool(0)

	keycfgstore := config.NewInMemoryConfigStore()
	keycfgmr := config.NewKeyConfigManager(keycfgstore)

	keystatestore := state.NewInMemoryStateStore()
	keystatemgr := state.NewMPCStateManager(keystatestore)

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
	eddsa_km := ed25519.NewEd25519KeyManagerImpl(ed_ks, sch_ks, vss_km)

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

	return NewFROSTKeygen(
		keycfgmr,
		keystatemgr,
		msgmgr,
		bcstmgr,
		eddsa_km,
		ed_vss_km,
		vss_km,
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
		mpckg := newFROSTKeygen()
		kgs = append(kgs, mpckg)
		_, err := mpckg.Start(cfg)(nil)
		require.NoError(t, err, "round creation should not result in an error")
		// rounds = append(rounds, r)
	}

	for {
		rounds, done, err := testRounds(kgs, keyID)
		require.NoError(t, err, "failed to process round")
		if done {
			for _, r := range rounds {
				r, ok := r.(*round.Output)
				if ok {
					res := r.Result.(*Config)
					fmt.Printf("Output: %x\n", res.PublicKey.Bytes())
				}
			}
			break
		}
	}
}

func testRounds(kgs []protocol.Processor, keyID string) ([]round.Session, bool, error) {
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
			return nil, false, err
		}
		rounds[idx] = r
	}
	if _, err = checkAllRoundsSame(rounds); err != nil {
		return nil, false, err
	}

	// get the second set of messages
	for id := range kgs {
		idx := id
		kg := kgs[idx]
		errGroup.Go(func() error {
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
		return nil, false, err
	}
	close(out)

	// Check that all rounds are the same type
	if roundType, err = checkAllRoundsSame(rounds); err != nil {
		return nil, false, err
	}
	if roundType.String() == reflect.TypeOf(&round.Output{}).String() {
		return rounds, true, nil
	}
	if roundType.String() == reflect.TypeOf(&round.Abort{}).String() {
		return rounds, true, nil
	}

	for msg := range out {
		msgBytes, err := cbor.Marshal(msg.Content)
		if err != nil {
			return nil, false, err
		}
		for _, kg := range kgs {
			kg := kg
			r, err := kg.GetRound(keyID)
			if err != nil {
				return nil, false, err
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
			return nil, false, err
		}
	}

	return rounds, false, nil
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
