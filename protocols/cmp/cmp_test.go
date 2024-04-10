package cmp

import (
	"crypto/rand"
	"math"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/mr-shifu/mpc-lib/core/ecdsa"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/party"
	"github.com/mr-shifu/mpc-lib/core/pool"
	"github.com/mr-shifu/mpc-lib/core/protocol"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/lib/test"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/vault"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func do(t *testing.T, id party.ID, ids []party.ID, threshold int, message []byte, pl *pool.Pool, n *test.Network, wg *sync.WaitGroup) {
	defer wg.Done()

	keyID := uuid.New().String()
	ksf := &keystore.InmemoryKeystoreFactory{}
	krf := &keyopts.InMemoryKeyOptsFactory{}
	vf := &vault.InmemoryVaultFactory{}
	keycfgstore := config.NewInMemoryConfigStore()
	signcfgstore := config.NewInMemoryConfigStore()

	mpc := NewMPC(ksf, krf, vf, keycfgstore, signcfgstore, pl)

	h, err := protocol.NewMultiHandler(
		mpc.Keygen(keyID, curve.Secp256k1{}, id, ids, threshold, pl),
		// Keygen(keyID, curve.Secp256k1{}, id, ids, threshold, pl), 
		nil)
	require.NoError(t, err)
	test.HandlerLoop(id, h, n)
	r, err := h.Result()
	require.NoError(t, err)
	require.IsType(t, &Config{}, r)
	c := r.(*Config)

	signID := uuid.New().String()
	info := round.Info{
		ProtocolID: 	 "cmp/sign",
		FinalRoundNumber: 5,
		SelfID:           id,
		PartyIDs:         ids,
		Threshold:        threshold,
		Group:            curve.Secp256k1{},
	}
	mpc.Sign(signID, keyID, info, ids, message, pl)
	h, err = protocol.NewMultiHandler(mpc.Sign(signID, keyID, info, ids, message, pl), nil)
	require.NoError(t, err)
	test.HandlerLoop(c.ID, h, n)

	signResult, err := h.Result()
	require.NoError(t, err)
	require.IsType(t, &ecdsa.Signature{}, signResult)
	signature := signResult.(*ecdsa.Signature)
	assert.True(t, signature.Verify(c.PublicPoint(), message))
}

func TestCMP(t *testing.T) {
	N := 3
	T := N - 1
	message := []byte("hello")

	partyIDs := test.PartyIDs(N)

	n := test.NewNetwork(partyIDs)

	var wg sync.WaitGroup
	wg.Add(N)
	for _, id := range partyIDs {
		pl := pool.NewPool(3)
		defer pl.TearDown()
		go do(t, id, partyIDs, T, message, pl, n, &wg)
	}
	wg.Wait()
}

func TestStart(t *testing.T) {
	group := curve.Secp256k1{}
	N := 6
	T := 3
	pl := pool.NewPool(0)
	defer pl.TearDown()
	configs, partyIDs := test.GenerateConfig(group, N, T, rand.Reader, pl)

	info := round.Info{
		ProtocolID:       "cmp/keygen-threshold",
		FinalRoundNumber: 5,
		SelfID:           partyIDs[0],
		PartyIDs:         partyIDs,
		Threshold:        T,
		Group:            group,
	}

	ksf := &keystore.InmemoryKeystoreFactory{}
	krf := &keyopts.InMemoryKeyOptsFactory{}
	vf := &vault.InmemoryVaultFactory{}
	keycfgstore := config.NewInMemoryConfigStore()
	signcfgstore := config.NewInMemoryConfigStore()

	mpc := NewMPC(ksf, krf, vf, keycfgstore, signcfgstore, pl)

	m := []byte("HELLO")
	selfID := partyIDs[0]
	c := configs[selfID]
	tests := []struct {
		name      string
		partyIDs  []party.ID
		threshold int
	}{
		{
			"N threshold",
			partyIDs,
			N,
		},
		{
			"T threshold",
			partyIDs[:T],
			N,
		},
		{
			"-1 threshold",
			partyIDs,
			-1,
		},
		{
			"max threshold",
			partyIDs,
			math.MaxUint32,
		},
		{
			"max threshold -1",
			partyIDs,
			math.MaxUint32 - 1,
		},
		{
			"no self",
			partyIDs[1:],
			T,
		},
		{
			"duplicate self",
			append(partyIDs, selfID),
			T,
		},
		{
			"duplicate other",
			append(partyIDs, partyIDs[1]),
			T,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyID := uuid.New().String()
			c.Threshold = tt.threshold
			var err error
			_, err = mpc.Keygen(keyID, group, selfID, tt.partyIDs, tt.threshold, pl)(nil)
			t.Log(err)
			assert.Error(t, err)

			signID := uuid.New().String()
			_, err = mpc.Sign(signID, keyID, info, tt.partyIDs, m, pl)(nil)
			t.Log(err)
			assert.Error(t, err)
		})
	}
}
