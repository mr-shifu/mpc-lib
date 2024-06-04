package ed25519

import (
	"fmt"
	"testing"

	ed "filippo.io/edwards25519"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
	"github.com/stretchr/testify/assert"
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
	rr := r.(*Ed25519Impl)

	z := ed.NewScalar().Multiply(ks, ms)

	assert.Equal(t, rr.s.Equal(z), 1)
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

	r := k.MultiplyAdd(ms, c)

	z := ed.NewScalar().MultiplyAdd(ks, ms, cs)

	assert.Equal(t, r.Equal(z), 1)
}

func TestSerDe(t *testing.T) {
	k, err := GenerateKey()
	assert.NoError(t, err)

	key := k.(*Ed25519Impl)

	pb := key.a.Bytes()

	pk, err := new(ed.Point).SetBytes(pb)
	assert.NoError(t, err)
	assert.Equal(t, 1, pk.Equal(key.a))

	fmt.Printf("pb: %v\n", pk)
	fmt.Printf("pb: %v\n", key.a)

	x, err := sample.Ed25519Scalar(nil)
	assert.NoError(t, err)
	x1 := k.Multiply(x)
	x1Key := x1.(*Ed25519Impl)

	y := new(ed.Point).Set(key.a)
	y.ScalarMult(x, y)

	assert.Equal(t, 1, new(ed.Point).ScalarBaseMult(x1Key.s).Equal(y))
	assert.Equal(t, 1, x1Key.a.Equal(y))
}
