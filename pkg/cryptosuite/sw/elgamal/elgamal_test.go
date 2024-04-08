package elgamal

import (
	"crypto/rand"
	"testing"

	"github.com/mr-shifu/mpc-lib/core/elgamal"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/vault"
	"github.com/stretchr/testify/assert"
)

func TestElgamal(t *testing.T) {
	// create a new in-memory keystore
	el_vault := vault.NewInMemoryVault()
	el_kr := keyopts.NewInMemoryKeyOpts()
	ks := keystore.NewInMemoryKeystore(el_vault, el_kr)

	// create a new ElGamal key manager
	mgr := NewElgamalKeyManager(ks, &Config{Group: curve.Secp256k1{}})

	// generate a new ElGamal key pair
	opts := keyopts.Options{}
	opts.Set("ID", 123, "partyID", 1)
	key, err := mgr.GenerateKey(opts)
	assert.NoError(t, err)
	keyBytes, err := key.Bytes()
	assert.NoError(t, err)
	assert.NotNil(t, keyBytes)

	// get SKI from the key
	ski := key.SKI()
	assert.NotNil(t, ski)

	// retreive the key from the keystore
	newKey, err := mgr.GetKey(opts)
	assert.NoError(t, err)
	newKeyBytes, err := newKey.Bytes()
	assert.NoError(t, err)
	assert.NotNil(t, newKeyBytes)
	assert.Equal(t, key.Private(), newKey.Private())
	assert.Equal(t, keyBytes, newKeyBytes)

	// Encrypt a random message with the public key
	msg := sample.Scalar(rand.Reader, curve.Secp256k1{})
	ct, nonce, err := mgr.Encrypt(msg, opts)
	assert.NoError(t, err)
	assert.NotNil(t, ct)
	assert.NotNil(t, nonce)

	// validate ciphertext
	ciphertext := elgamal.NewCiphertext(curve.Secp256k1{})
	ciphertext.UnmarshalBinary(ct)
	v := ciphertext.Valid()
	assert.True(t, v)
}
