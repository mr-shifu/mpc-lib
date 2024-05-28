package ed25519

import (
	"testing"

	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/vault"
	"github.com/stretchr/testify/assert"
)

func getKeyManager() *Ed25519KeyManagerImpl {
	ed_keyopts := keyopts.NewInMemoryKeyOpts()
	ed_vault := vault.NewInMemoryVault()
	ed_ks := keystore.NewInMemoryKeystore(ed_vault, ed_keyopts)

	sch_keyopts := keyopts.NewInMemoryKeyOpts()
	sch_vault := vault.NewInMemoryVault()
	sch_ks := keystore.NewInMemoryKeystore(sch_vault, sch_keyopts)

	return NewEd25519KeyManagerImpl(ed_ks, sch_ks)
}

func TestEd25519KeyManagerImpl_GenerateKey(t *testing.T) {
	mgr := getKeyManager()

	opts := keyopts.Options{}
	opts.Set("id", "1", "partyid", "a")
	k, err := mgr.GenerateKey(opts)
	assert.NoError(t, err)
	assert.NotNil(t, k)
	assert.True(t, k.Private())

	kk, err := mgr.GetKey(opts)
	assert.NoError(t, err)
	assert.NotNil(t, kk)
	assert.True(t, kk.Private())

	assert.Equal(t, k.SKI(), kk.SKI())
}

func TestEd25519KeyManagerImpl_ImportKey(t *testing.T) {
	mgr := getKeyManager()

	k, err := GenerateKey()
	assert.NoError(t, err)

	opts := keyopts.Options{}
	opts.Set("id", "1", "partyid", "a")
	_, err = mgr.ImportKey(k, opts)
	assert.NoError(t, err)

	kk, err := mgr.GetKey(opts)
	assert.NoError(t, err)

	assert.Equal(t, k.SKI(), kk.SKI())
	assert.True(t, kk.Private())
}

func TestEd25519KeyManagerImpl_ImportKeyBytes(t *testing.T) {
	mgr := getKeyManager()

	k, err := GenerateKey()
	assert.NoError(t, err)

	kb, err := k.Bytes()
	assert.NoError(t, err)

	opts := keyopts.Options{}
	opts.Set("id", "1", "partyid", "a")
	_, err = mgr.ImportKey(kb, opts)
	assert.NoError(t, err)

	kk, err := mgr.GetKey(opts)
	assert.NoError(t, err)

	assert.Equal(t, k.SKI(), kk.SKI())
	assert.True(t, kk.Private())
}

func TestEd25519KeyManagerImpl_ImportPublicKey(t *testing.T) {
	mgr := getKeyManager()

	k, err := GenerateKey()
	assert.NoError(t, err)

	pk, err := NewKey(nil, k.(*Ed25519Impl).a)
	assert.NoError(t, err)

	kb, err := pk.Bytes()
	assert.NoError(t, err)

	opts := keyopts.Options{}
	opts.Set("id", "1", "partyid", "a")
	_, err = mgr.ImportKey(kb, opts)
	assert.NoError(t, err)

	kk, err := mgr.GetKey(opts)
	assert.NoError(t, err)

	assert.Equal(t, k.SKI(), kk.SKI())
	assert.False(t, kk.Private())
}

func TestEd25519KeyManager_SchnorrProof(t *testing.T) {
	opts1 := keyopts.Options{}
	opts1.Set("id", "1", "partyid", "a")

	hahs_keyopts := keyopts.NewInMemoryKeyOpts()
	hahs_vault := vault.NewInMemoryVault()
	hash_ks := keystore.NewInMemoryKeystore(hahs_vault, hahs_keyopts)
	hash_mgr := hash.NewHashManager(hash_ks)
	h := hash_mgr.NewHasher("test", opts1)

	mgr1 := getKeyManager()
	mgr2 := getKeyManager()

	k1, err := mgr1.GenerateKey(opts1)
	assert.NoError(t, err)

	k2, err := NewKey(nil, k1.(*Ed25519Impl).a)
	assert.NoError(t, err)
	_, err = mgr2.ImportKey(k2, opts1)
	assert.NoError(t, err)

	proof, err := mgr1.NewSchnorrProof(h.Clone(), opts1)
	assert.NoError(t, err)

	proofBytes := proof.Bytes()
	assert.Equal(t, SchnorrProofSizeNoC, len(proofBytes))

	err = mgr2.ImportSchnorrProof(proofBytes, opts1)
	assert.NoError(t, err)

	v, err := mgr2.VerifySchnorrProof(h.Clone(), opts1)
	assert.NoError(t, err)
	assert.True(t, v)
}
