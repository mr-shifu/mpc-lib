package ecdsa

import (
	"crypto/rand"
	"testing"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss"
	"github.com/mr-shifu/mpc-lib/pkg/keystore"
	"github.com/stretchr/testify/assert"
)

func newEcdsakeyManager() *ECDSAKeyManager {
	cfg := &Config{curve.Secp256k1{}}
	ks := keystore.NewInMemoryKeystore()
	schstore := keystore.NewInMemoryKeystore()

	vss_ks := keystore.NewInMemoryKeystore()
	sharestore := vss.NewInMemoryVSSShareStore()
	vssmgr := vss.NewVssKeyManager(vss_ks, sharestore, cfg.Group)

	mgr := NewECDSAKeyManager(ks, schstore, vssmgr, cfg)

	return mgr
}

func TestGenerateKey(t *testing.T) {
	mgr := newEcdsakeyManager()

	// Must Generate a new key successfully
	key, err := mgr.GenerateKey()
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.True(t, key.Private())
	// Must serialize key successfully
	kb, err := key.Bytes()
	assert.NoError(t, err)

	// Must retreive key successfully
	newKey, err := mgr.GetKey(key.SKI())
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
	key := NewECDSAKey(sk, pk, curve.Secp256k1{})
	kb, err := key.Bytes()
	assert.NoError(t, err)

	_, err = mgr.ImportKey(key)
	assert.NoError(t, err)

	newKey, err := mgr.GetKey(key.SKI())
	assert.NoError(t, err)
	assert.True(t, newKey.Private())
	newkb, err := newKey.Bytes()
	assert.NoError(t, err)

	assert.Equal(t, kb, newkb)
}

func TestImportPublicKey(t *testing.T) {
	mgr := newEcdsakeyManager()

	_, pk := sample.ScalarPointPair(rand.Reader, curve.Secp256k1{})
	key := NewECDSAKey(nil, pk, curve.Secp256k1{})
	kb, err := key.Bytes()
	assert.NoError(t, err)

	_, err = mgr.ImportKey(key)
	assert.NoError(t, err)

	newKey, err := mgr.GetKey(key.SKI())
	assert.NoError(t, err)
	assert.False(t, newKey.Private())
	newkb, err := newKey.Bytes()
	assert.NoError(t, err)

	assert.Equal(t, kb, newkb)
}

func TestSchnorr(t *testing.T) {
	mgr1 := newEcdsakeyManager()
	mgr2 := newEcdsakeyManager()

	hs := keystore.NewInMemoryKeystore()
	hash_mgr := hash.NewHashManager(hs)
	h := hash_mgr.NewHasher("test")

	// 1. Generate a new key by mgr1
	key, err := mgr1.GenerateKey()
	assert.NoError(t, err)

	// 2. Import the key by mgr2
	_, err = mgr2.ImportKey(NewECDSAKey(nil, key.PublicKeyRaw(), curve.Secp256k1{}))
	assert.NoError(t, err)

	// 3. Generate Schnorr commitment by mgr1
	commitment, err := key.NewSchnorrCommitment()
	assert.NoError(t, err)

	// 4. Import Schnorr commitment by mgr2
	newKey, err := mgr2.GetKey(key.SKI())
	assert.NoError(t, err)
	err = newKey.ImportSchnorrCommitment(commitment)
	assert.NoError(t, err)

	// 5. Generate Schnorr proof by mgr1
	proof, err := key.GenerateSchnorrProof(h.Clone())
	assert.NoError(t, err)

	// 6. Verify Schnorr proof by mgr2
	verified, err := newKey.VerifySchnorrProof(h.Clone(), proof)
	assert.NoError(t, err)
	assert.True(t, verified)
}

func TestGenerateVSS(t *testing.T) {
	
}

func TestImportVSS(t *testing.T) {
	mgr1 := newEcdsakeyManager()
	mgr2 := newEcdsakeyManager()

	// 1. Generate a new key by mgr
	key1, err := mgr1.GenerateKey()
	assert.NoError(t, err)

	// 2. Import the key by mgr2
	_, err = mgr2.ImportKey(NewECDSAKey(nil, key1.PublicKeyRaw(), curve.Secp256k1{}))
	assert.NoError(t, err)

	// 3. Generate VSS secrets by mgr1
	err = key1.GenerateVSSSecrets(3)
	assert.NoError(t, err)
	vss1, err := key1.VSS()
	assert.NoError(t, err)
	assert.True(t, vss1.Private())

	// 4. Import VSS secrets by mgr2
	exp, err := vss1.ExponentsRaw()
	assert.NoError(t, err)
	exp_bytes, err := exp.MarshalBinary()
	assert.NoError(t, err)
	key2, err := mgr2.GetKey(key1.SKI())
	assert.NoError(t, err)
	err = key2.ImportVSSSecrets(exp_bytes)
	assert.NoError(t, err)
	assert.False(t, key2.Private())
}
