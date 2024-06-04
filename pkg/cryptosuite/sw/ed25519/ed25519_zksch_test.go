package ed25519

import (
	"testing"

	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/vault"
	"github.com/stretchr/testify/assert"
)

func TestGenerateSchnorrProof(t *testing.T) {
	hahs_keyopts := keyopts.NewInMemoryKeyOpts()
	hahs_vault := vault.NewInMemoryVault()
	hash_ks := keystore.NewInMemoryKeystore(hahs_vault, hahs_keyopts)
	hash_mgr := hash.NewHashManager(hash_ks)

	opts := keyopts.Options{}
	opts.Set("id", "1", "partyid", "a")
	h := hash_mgr.NewHasher("test", opts)

	k, err := GenerateKey()
	assert.NoError(t, err)

	proof, err := k.NewScnorrProof(h.Clone())
	assert.NoError(t, err)

	v, err := k.VerifySchnorrProof(h.Clone(), proof)
	assert.NoError(t, err)
	assert.True(t, v)
}

func TestSerializeDeserializeProof(t *testing.T) {
	hahs_keyopts := keyopts.NewInMemoryKeyOpts()
	hahs_vault := vault.NewInMemoryVault()
	hash_ks := keystore.NewInMemoryKeystore(hahs_vault, hahs_keyopts)
	hash_mgr := hash.NewHashManager(hash_ks)

	opts := keyopts.Options{}
	opts.Set("id", "1", "partyid", "a")
	h := hash_mgr.NewHasher("test", opts)

	k, err := GenerateKey()
	assert.NoError(t, err)

	proof, err := k.NewScnorrProof(h.Clone())
	assert.NoError(t, err)

	pb := proof.bytes()
	assert.NotNil(t, pb)

	newProof := &Proof{}
	err = newProof.fromBytes(pb)
	assert.NoError(t, err)

	v1, err := k.VerifySchnorrProof(h.Clone(), proof)
	assert.NoError(t, err)
	assert.True(t, v1)

	v2, err := k.VerifySchnorrProof(h.Clone(), newProof)
	assert.NoError(t, err)
	assert.True(t, v2)
}
