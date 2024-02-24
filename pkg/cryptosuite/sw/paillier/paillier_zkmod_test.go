package paillier

import (
	"testing"

	"github.com/mr-shifu/mpc-lib/core/hash"
	"github.com/mr-shifu/mpc-lib/core/pool"
	"github.com/mr-shifu/mpc-lib/pkg/keystore"
	"github.com/stretchr/testify/assert"
)

func TestZKMod(t *testing.T) {
	pl := pool.NewPool(0)

	ks := keystore.NewInMemoryKeystore()
	paillier := NewPaillierKeyManager(ks, pl)

	pk, err := paillier.GenerateKey()
	assert.NoError(t, err)

	proof := pk.NewZKModProof(hash.New(), pl)

	verified := pk.VerifyZKMod(proof, hash.New(), pl)

	assert.True(t, verified)
}
