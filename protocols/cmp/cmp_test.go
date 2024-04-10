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
	"github.com/mr-shifu/mpc-lib/lib/test"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/config"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/state"
	"github.com/mr-shifu/mpc-lib/pkg/vault"
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
	keystatestore := state.NewInMemoryStateStore()
	signstatestore := state.NewInMemoryStateStore()

	mpc := NewMPC(ksf, krf, vf, keycfgstore, signcfgstore, keystatestore, signstatestore, pl)

	keycfg := config.NewKeyConfig(keyID, curve.Secp256k1{}, threshold, id, ids)
	h, err := protocol.NewMultiHandler(
		mpc.Keygen(keycfg, pl),
		nil)
	require.NoError(t, err)
	test.HandlerLoop(id, h, n)
	r, err := h.Result()
	require.NoError(t, err)
	require.IsType(t, &Config{}, r)
	c := r.(*Config)

	signID := uuid.New().String()
	signcfg := config.NewSignConfig(signID, keyID, curve.Secp256k1{}, threshold, id, ids)
	mpc.Sign(signcfg, message, pl)
	h, err = protocol.NewMultiHandler(mpc.Sign(signcfg, message, pl), nil)
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

	ksf := &keystore.InmemoryKeystoreFactory{}
	krf := &keyopts.InMemoryKeyOptsFactory{}
	vf := &vault.InmemoryVaultFactory{}
	keycfgstore := config.NewInMemoryConfigStore()
	signcfgstore := config.NewInMemoryConfigStore()
	keystatestore := state.NewInMemoryStateStore()
	signstatestore := state.NewInMemoryStateStore()

	mpc := NewMPC(ksf, krf, vf, keycfgstore, signcfgstore, keystatestore, signstatestore, pl)

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
			keycfg := config.NewKeyConfig(keyID, group, tt.threshold, selfID, tt.partyIDs)
			var err error
			_, err = mpc.Keygen(keycfg, pl)(nil)
			t.Log(err)
			assert.Error(t, err)

			signID := uuid.New().String()
			signcfg := config.NewSignConfig(signID, keyID, group, tt.threshold, selfID, tt.partyIDs)
			_, err = mpc.Sign(signcfg, m, pl)(nil)
			t.Log(err)
			assert.Error(t, err)
		})
	}
}
