package paillier

import (
	"testing"

	"github.com/mr-shifu/mpc-lib/core/pool"
	zkfac "github.com/mr-shifu/mpc-lib/core/zk/fac"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/vault"
	"github.com/stretchr/testify/assert"
)

func TestZKFAC(t *testing.T) {
	pl := pool.NewPool(0)

	hs_vault := vault.NewInMemoryVault()
	hs_kr := keyopts.NewInMemoryKeyOpts()
	hs := keystore.NewInMemoryKeystore(hs_vault, hs_kr)
	mgr := hash.NewHashManager(hs)

	opts1 := keyopts.Options{}
	opts1.Set("ID", 123, "partyID", 1)

	opts2 := keyopts.Options{}
	opts2.Set("ID", 123, "partyID", 2)

	h1 := mgr.NewHasher("key1", opts1)
	h2 := mgr.NewHasher("key2", opts2)

	
	ks_vault := vault.NewInMemoryVault()
	ks_kr := keyopts.NewInMemoryKeyOpts()
	ks := keystore.NewInMemoryKeystore(ks_vault, ks_kr)
	paillier := NewPaillierKeyManager(ks, pl)

	pk, err := paillier.GenerateKey(opts1)
	assert.NoError(t, err)

	pkx, err := paillier.GenerateKey(opts2)
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
