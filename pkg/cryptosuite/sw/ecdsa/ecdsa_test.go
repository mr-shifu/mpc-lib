package ecdsa

import (
	"crypto/rand"
	"testing"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/vault"
	"github.com/stretchr/testify/assert"
)

func newEcdsakeyManager() *ECDSAKeyManagerImpl {
	cfg := &Config{curve.Secp256k1{}}

	ec_vault := vault.NewInMemoryVault()
	ec_kr := keyopts.NewInMemoryKeyOpts()
	ks := keystore.NewInMemoryKeystore(ec_vault, ec_kr)

	sch_vault := vault.NewInMemoryVault()
	sch_kr := keyopts.NewInMemoryKeyOpts()
	schstore := keystore.NewInMemoryKeystore(sch_vault, sch_kr)

	vss_vault := vault.NewInMemoryVault()
	vss_kr := keyopts.NewInMemoryKeyOpts()
	vss_ks := keystore.NewInMemoryKeystore(vss_vault, vss_kr)
	vssmgr := vss.NewVssKeyManager(vss_ks, cfg.Group)

	mgr := NewECDSAKeyManager(ks, schstore, vssmgr, cfg)

	return mgr
}

func TestGenerateKey(t *testing.T) {
	mgr := newEcdsakeyManager()

	opts, err := keyopts.NewOptions().Set("id", "123", "partyid", "1")
	assert.NoError(t, err)

	// Must Generate a new key successfully
	key, err := mgr.GenerateKey(opts)
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.True(t, key.Private())
	// Must serialize key successfully
	kb, err := key.Bytes()
	assert.NoError(t, err)

	// Must retreive key successfully
	newKey, err := mgr.GetKey(opts)
	assert.NoError(t, err)
	// Must serialize key successfully
	newkb, err := newKey.Bytes()
	assert.NoError(t, err)
	// new key must be the same as original key
	assert.Equal(t, kb, newkb)
}

func TestImportPrivateKey(t *testing.T) {
	mgr := newEcdsakeyManager()

	sk, pk := sample.ScalarPointPair(rand.Reader, curve.Secp256k1{})
	key := NewKey(sk, pk, curve.Secp256k1{})
	kb, err := key.Bytes()
	assert.NoError(t, err)

	opts, err := keyopts.NewOptions().Set("id", "123", "partyid", "1")
	assert.NoError(t, err)

	_, err = mgr.ImportKey(key, opts)
	assert.NoError(t, err)

	newKey, err := mgr.GetKey(opts)
	assert.NoError(t, err)
	assert.True(t, newKey.Private())
	newkb, err := newKey.Bytes()
	assert.NoError(t, err)

	assert.Equal(t, kb, newkb)
}

func TestImportPublicKey(t *testing.T) {
	mgr := newEcdsakeyManager()

	_, pk := sample.ScalarPointPair(rand.Reader, curve.Secp256k1{})
	key := NewKey(nil, pk, curve.Secp256k1{})
	kb, err := key.Bytes()
	assert.NoError(t, err)

	opts, err := keyopts.NewOptions().Set("id", "123", "partyid", "1")
	assert.NoError(t, err)

	_, err = mgr.ImportKey(key, opts)
	assert.NoError(t, err)

	newKey, err := mgr.GetKey(opts)
	assert.NoError(t, err)
	assert.False(t, newKey.Private())
	newkb, err := newKey.Bytes()
	assert.NoError(t, err)

	assert.Equal(t, kb, newkb)
}

// func TestGenerateSchnorrProof(t *testing.T) {
// 	hahs_keyopts := keyopts.NewInMemoryKeyOpts()
// 	hahs_vault := vault.NewInMemoryVault()
// 	hash_ks := keystore.NewInMemoryKeystore(hahs_vault, hahs_keyopts)
// 	hash_mgr := hash.NewHashManager(hash_ks)

// 	opts, err := keyopts.NewOptions().Set("id", "1", "partyid", "a")
// 	assert.NoError(t, err)
// 	h := hash_mgr.NewHasher("test", opts)

// 	group := curve.Secp256k1{}
// 	k, err := GenerateKey(group)
// 	assert.NoError(t, err)

// 	proof, err := k.NewScnorrProof(h.Clone())
// 	assert.NoError(t, err)

// 	v, err := k.VerifySchnorrProof(h.Clone(), proof)
// 	assert.NoError(t, err)
// 	assert.True(t, v)
// }

// func TestSchnorr(t *testing.T) {
// 	mgr1 := newEcdsakeyManager()
// 	mgr2 := newEcdsakeyManager()

// 	sch_vault := vault.NewInMemoryVault()
// 	sch_kr := keyopts.NewInMemoryKeyOpts()

// 	hs := keystore.NewInMemoryKeystore(sch_vault, sch_kr)
// 	hash_mgr := hash.NewHashManager(hs)
// 	opts, err := keyopts.NewOptions().Set("id", "123", "partyid", "1")
// 	assert.NoError(t, err)
// 	h := hash_mgr.NewHasher("test", opts)

// 	// 1. Generate a new key by mgr1
// 	key, err := mgr1.GenerateKey(opts)
// 	assert.NoError(t, err)

// 	// 2. Import the key by mgr2
// 	k := NewKey(nil, key.PublicKeyRaw(), curve.Secp256k1{})
// 	_, err = mgr2.ImportKey(k, opts)
// 	assert.NoError(t, err)

// 	// 3. Generate Schnorr commitment by mgr1
// 	commitment, err := key.New
// 	assert.NoError(t, err)

// 	// 4. Import Schnorr commitment by mgr2
// 	newKey, err := mgr2.GetKey(opts)
// 	assert.NoError(t, err)
// 	err = newKey.ImportSchnorrCommitment(commitment)
// 	assert.NoError(t, err)

// 	// 5. Generate Schnorr proof by mgr1
// 	proof, err := key.GenerateSchnorrProof(h.Clone())
// 	assert.NoError(t, err)

// 	// 6. Verify Schnorr proof by mgr2
// 	verified, err := newKey.VerifySchnorrProof(h.Clone(), proof)
// 	assert.NoError(t, err)
// 	assert.True(t, verified)
// }

// func TestImportVSS(t *testing.T) {
// 	mgr1 := newEcdsakeyManager()
// 	mgr2 := newEcdsakeyManager()

// 	opts, err := keyopts.NewOptions().Set("id", "123", "partyid", "1")
// 	assert.NoError(t, err)

// 	// 1. Generate a new key by mgr
// 	key1, err := mgr1.GenerateKey(opts)
// 	assert.NoError(t, err)

// 	// 2. Import the key by mgr2
// 	key := NewKey(nil, key1.PublicKeyRaw(), curve.Secp256k1{})
// 	_, err = mgr2.ImportKey(key, opts)
// 	assert.NoError(t, err)

// 	// 3. Generate VSS secrets by mgr1
// 	err = key1.GenerateVSSSecrets(3, opts)
// 	assert.NoError(t, err)
// 	vss1, err := key1.VSS(opts)
// 	assert.NoError(t, err)
// 	assert.True(t, vss1.Private())

// 	// 4. Import VSS secrets by mgr2
// 	// exp, err := vss1.ExponentsRaw()
// 	// assert.NoError(t, err)
// 	// exp_bytes, err := exp.MarshalBinary()
// 	// assert.NoError(t, err)
// 	// key2, err := mgr2.GetKey(opts)
// 	// assert.NoError(t, err)
// 	// err = key2.ImportVSSSecrets(exp_bytes, opts)
// 	// assert.NoError(t, err)
// 	// assert.False(t, key2.Private())
// }
