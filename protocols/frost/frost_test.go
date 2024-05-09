package frost

import (
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/mr-shifu/mpc-lib/core/eddsa"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/party"
	"github.com/mr-shifu/mpc-lib/core/pool"
	"github.com/mr-shifu/mpc-lib/core/protocol"
	"github.com/mr-shifu/mpc-lib/lib/test"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/config"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/message"
	result "github.com/mr-shifu/mpc-lib/pkg/mpc/result/eddsa"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/state"
	"github.com/mr-shifu/mpc-lib/pkg/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func do(t *testing.T, id party.ID, ids []party.ID, threshold int, msg []byte, pl *pool.Pool, n *test.Network, wg *sync.WaitGroup) {
	defer wg.Done()

	keyID := uuid.New().String()
	ksf := &keystore.InmemoryKeystoreFactory{}
	krf := &keyopts.InMemoryKeyOptsFactory{}
	vf := &vault.InmemoryVaultFactory{}
	keycfgstore := config.NewInMemoryConfigStore()
	signcfgstore := config.NewInMemoryConfigStore()
	keystatestore := state.NewInMemoryStateStore()
	signstatestore := state.NewInMemoryStateStore()
	msgstore := message.NewInMemoryMessageStore()
	bcststore := message.NewInMemoryMessageStore()

	frost := NewFROST(ksf, krf, vf, keycfgstore, signcfgstore, keystatestore, signstatestore, msgstore, bcststore, pl)

	keycfg := config.NewKeyConfig(keyID, curve.Secp256k1{}, threshold, id, ids)
	h, err := protocol.NewMultiHandler(frost.Keygen(keycfg, pl), nil)
	require.NoError(t, err)
	test.HandlerLoop(id, h, n)
	r, err := h.Result()
	require.NoError(t, err)
	require.IsType(t, &Config{}, r)
	c := r.(*Config)

	signID := uuid.New().String()
	signcfg := config.NewSignConfig(signID, keyID, curve.Secp256k1{}, threshold, id, ids, msg)
	frost.Sign(signcfg, pl)
	h, err = protocol.NewMultiHandler(frost.Sign(signcfg, pl), nil)
	require.NoError(t, err)
	test.HandlerLoop(c.ID, h, n)

	signResult, err := h.Result()
	require.NoError(t, err)
	require.IsType(t, &result.EddsaSignature{}, signResult)
	signature := eddsa.Signature{
		R: signResult.(*result.EddsaSignature).R(),
		Z: signResult.(*result.EddsaSignature).Z(),
	}
	assert.True(t, eddsa.Verify(c.PublicKey, signature, msg))
}

func TestFROST(t *testing.T) {
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
