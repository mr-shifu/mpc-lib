package paillier

import (
	"testing"

	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	"github.com/mr-shifu/mpc-lib/core/pool"
	"github.com/mr-shifu/mpc-lib/pkg/keystore"
	"github.com/stretchr/testify/assert"
)

func TestZKMod(t *testing.T) {
	pl := pool.NewPool(0)

	hs := keystore.NewInMemoryKeystore()
	mgr := hash.NewHashManager(hs)
	
	h1 := mgr.NewHasher("key1")
	h2 := mgr.NewHasher("key2")

	ks := keystore.NewInMemoryKeystore()
	paillier := NewPaillierKeyManager(ks, pl)

	pk, err := paillier.GenerateKey()
	assert.NoError(t, err)

	proof := pk.NewZKModProof(h1, pl)

	verified := pk.VerifyZKMod(proof, h2, pl)

	assert.True(t, verified)
}
