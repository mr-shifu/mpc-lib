package ed25519

import (
	"testing"

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
