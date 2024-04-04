package paillier

import (
	"testing"

	"github.com/mr-shifu/mpc-lib/core/pool"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/vault"
	"github.com/stretchr/testify/assert"
)

func TestZKMod(t *testing.T) {
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

	proof := pk.NewZKModProof(h1, pl)

	verified := pk.VerifyZKMod(proof, h2, pl)

	assert.True(t, verified)
}
