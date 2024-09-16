package paillier

import (
	"crypto/rand"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
	"github.com/mr-shifu/mpc-lib/core/pool"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/vault"
	"github.com/stretchr/testify/assert"
)

func TestPaillier(t *testing.T) {
	pl := pool.NewPool(0)

	ks_vault := vault.NewInMemoryVault()
	ks_kr := keyopts.NewInMemoryKeyOpts()
	ks := keystore.NewInMemoryKeystore(ks_vault, ks_kr)

	mgr := NewPaillierKeyManager(ks, pl)

	// generate a new Paillier key pair
	opts, err := keyopts.NewOptions().Set("ID", 123, "partyID", 1)
	assert.NoError(t, err)
	key, err := mgr.GenerateKey(opts)
	assert.NoError(t, err)

	// retrieve the key from the keystore
	newKey, err := mgr.GetKey(opts)
	assert.NoError(t, err)
	assert.Equal(t, key.SKI(), newKey.SKI())

	// encode
	sc := sample.Scalar(rand.Reader, curve.Secp256k1{})
	msg := curve.MakeInt(sc)
	ct, _ := mgr.Encode(msg, opts)

	m, err := mgr.Decode(ct, opts)
	assert.NoError(t, err)

	eq := m.Eq(msg)
	assert.Equal(t, eq, saferith.Choice(0x1))

	// encode with nonce
	nonce := sample.UnitModN(rand.Reader, key.ParamN())
	ctn := mgr.EncWithNonce(msg, nonce, opts)

	m, _, err = mgr.DecodeWithNonce(ctn, opts)
	assert.NoError(t, err)

	eq = m.Eq(msg)
	assert.Equal(t, eq, saferith.Choice(0x1))

	v, err := mgr.ValidateCiphertexts(opts, ct, ctn)
	assert.NoError(t, err)
	assert.True(t, v)
}
