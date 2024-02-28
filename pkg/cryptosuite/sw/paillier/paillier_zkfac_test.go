package paillier

import (
	"testing"

	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	"github.com/mr-shifu/mpc-lib/core/pool"
	zkfac "github.com/mr-shifu/mpc-lib/core/zk/fac"
	"github.com/mr-shifu/mpc-lib/pkg/keystore"
	"github.com/stretchr/testify/assert"
)

func TestZKFAC(t *testing.T) {
	pl := pool.NewPool(0)

	hs := keystore.NewInMemoryKeystore()
	mgr := hash.NewHashManager(hs)
	
	h1 := mgr.NewHasher("key1")
	h2 := mgr.NewHasher("key2")

	ks := keystore.NewInMemoryKeystore()
	paillier := NewPaillierKeyManager(ks, pl)

	pk, err := paillier.GenerateKey()
	assert.NoError(t, err)

	pkx, err := paillier.GenerateKey()
	assert.NoError(t, err)
	pedx, err := pkx.DerivePedersenKey()
	assert.NoError(t, err)

	public := zkfac.Public{
		N:   pk.PublicKey().ParamN(),
		Aux: pedx.PublicKeyRaw(),
	}
	proof := pk.NewZKFACProof(h1, public)

	verified := pkx.VerifyZKFAC(proof, public, h2)

	assert.True(t, verified)
}
