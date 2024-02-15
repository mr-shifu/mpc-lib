package paillier

import (
	"crypto/rand"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
	"github.com/mr-shifu/mpc-lib/core/pool"
	"github.com/mr-shifu/mpc-lib/pkg/keystore"
	"github.com/stretchr/testify/assert"
)

func TestPaillier(t *testing.T) {
	pl := pool.NewPool(0)
	ks := keystore.NewInMemoryKeystore()

	mgr := NewPaillierKeyManager(ks, pl)

	// generate a new Paillier key pair
	key, err := mgr.GenerateKey()
	assert.NoError(t, err)

	// retrieve the key from the keystore
	newKey, err := mgr.GetKey(key.SKI())
	assert.NoError(t, err)
	assert.Equal(t, key.SKI(), newKey.SKI())

	// encode
	sc := sample.Scalar(rand.Reader, curve.Secp256k1{})
	msg := curve.MakeInt(sc)
	ct, _ := mgr.Encode(key.SKI(), msg)

	m, err := mgr.Decode(key.SKI(), ct)
	assert.NoError(t, err)

	eq := m.Eq(msg)
	assert.Equal(t, eq, saferith.Choice(0x1))

	// encode with nonce
	nonce := sample.UnitModN(rand.Reader, key.ParamN())
	ctn := mgr.EncWithNonce(key.SKI(), msg, nonce)

	m, _, err = mgr.DecodeWithNonce(key.SKI(), ctn)
	assert.NoError(t, err)

	eq = m.Eq(msg)
	assert.Equal(t, eq, saferith.Choice(0x1))

	v, err := mgr.ValidateCiphertexts(key.SKI(), ct, ctn)
	assert.NoError(t, err)
	assert.True(t, v)
}
