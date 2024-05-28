package ed25519

import (
	"testing"

	"github.com/stretchr/testify/assert"
	ed "filippo.io/edwards25519"
)

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	assert.NoError(t, err)
	assert.True(t, key.Private(), "Expected to be private key")

	kb, err := key.Bytes()
	assert.NoError(t, err)
	assert.Len(t, kb, PrivateKeySize, "Expected private key size")

	pub, err := FromPublicKey(kb[32:])
	assert.NoError(t, err)
	assert.False(t, pub.Private(), "Expected to be public key")

	prv, err := FromPrivateKey(kb)
	assert.NoError(t, err)
	assert.True(t, prv.Private(), "Expected to be private key")

	k := new(Ed25519Impl)
	err = k.FromBytes(kb)
	assert.NoError(t, err)

	skiFromKey := key.SKI()
	assert.NotNil(t, skiFromKey)

	skiFromPub := pub.SKI()
	assert.NotNil(t, skiFromPub)
	assert.Equal(t, skiFromKey, skiFromPub)

	skiFromPrv := prv.SKI()
	assert.NotNil(t, skiFromPrv)
	assert.Equal(t, skiFromKey, skiFromPrv)

	skiFromK := k.SKI()
	assert.NotNil(t, skiFromK)
	assert.Equal(t, skiFromKey, skiFromK)
}

func TestMultiply(t *testing.T) {
	k, err := GenerateKey()
	assert.NoError(t, err)

	m, err := GenerateKey()
	assert.NoError(t, err)

	ks := k.(*Ed25519Impl).s
	ms := m.(*Ed25519Impl).s

	r := k.Multiply(ms)

	z := ed.NewScalar().Multiply(ks, ms)

	assert.Equal(t, r.Equal(z), 1)
}

func TestMultiplyAdd(t *testing.T) {
	k, err := GenerateKey()
	assert.NoError(t, err)

	m, err := GenerateKey()
	assert.NoError(t, err)

	c, err := GenerateKey()
	assert.NoError(t, err)

	ks := k.(*Ed25519Impl).s
	ms := m.(*Ed25519Impl).s
	cs := c.(*Ed25519Impl).s

	r := k.MultiplyAdd(ms, cs)

	z := ed.NewScalar().MultiplyAdd(ks, ms, cs)

	assert.Equal(t, r.Equal(z), 1)
}