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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func do(t *testing.T, id party.ID, ids []party.ID, threshold int, message []byte, pl *pool.Pool, n *test.Network, wg *sync.WaitGroup) {
	defer wg.Done()

	keyID := uuid.New().String()

	h, err := protocol.NewMultiHandler(Keygen(keyID, curve.Secp256k1{}, id, ids, threshold, pl), nil)
	require.NoError(t, err)
	test.HandlerLoop(id, h, n)
	r, err := h.Result()
	require.NoError(t, err)
	require.IsType(t, &Config{}, r)
	c := r.(*Config)


	h, err = protocol.NewMultiHandler(Refresh(keyID, c, pl), nil)
	require.NoError(t, err)
	test.HandlerLoop(c.ID, h, n)

	r, err = h.Result()
	require.NoError(t, err)
	require.IsType(t, &Config{}, r)
	c = r.(*Config)

	h, err = protocol.NewMultiHandler(Sign(c, ids, message, pl), nil)
	require.NoError(t, err)
	test.HandlerLoop(c.ID, h, n)

	signResult, err := h.Result()
	require.NoError(t, err)
	require.IsType(t, &ecdsa.Signature{}, signResult)
	signature := signResult.(*ecdsa.Signature)
	assert.True(t, signature.Verify(c.PublicPoint(), message))

	h, err = protocol.NewMultiHandler(Presign(c, ids, pl), nil)
	require.NoError(t, err)

	test.HandlerLoop(c.ID, h, n)

	signResult, err = h.Result()
	require.NoError(t, err)
	require.IsType(t, &ecdsa.PreSignature{}, signResult)
	preSignature := signResult.(*ecdsa.PreSignature)
	assert.NoError(t, preSignature.Validate())

	h, err = protocol.NewMultiHandler(PresignOnline(c, preSignature, message, pl), nil)
	require.NoError(t, err)
	test.HandlerLoop(c.ID, h, n)

	signResult, err = h.Result()
	require.NoError(t, err)
	require.IsType(t, &ecdsa.Signature{}, signResult)
	signature = signResult.(*ecdsa.Signature)
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
			_, err = Keygen(keyID, group, selfID, tt.partyIDs, tt.threshold, pl)(nil)
			t.Log(err)
			assert.Error(t, err)

			_, err = Sign(c, tt.partyIDs, m, pl)(nil)
			t.Log(err)
			assert.Error(t, err)

			_, err = Presign(c, tt.partyIDs, pl)(nil)
			t.Log(err)
			assert.Error(t, err)
		})
	}
}
