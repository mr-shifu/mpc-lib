package zksch

import (
	"crypto/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	"github.com/mr-shifu/mpc-lib/pkg/keystore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSchPass(t *testing.T) {
	hs := keystore.NewInMemoryKeystore()
	mgr := hash.NewHashManager(hs)
	h := mgr.NewHasher("test")

	group := curve.Secp256k1{}

	a := NewRandomness(rand.Reader, group, nil)
	x, X := sample.ScalarPointPair(rand.Reader, group)

	proof := a.Prove(h.Clone(), X, x, nil)
	assert.True(t, proof.Verify(h.Clone(), X, a.Commitment(), nil), "failed passing test")
	assert.True(t, proof.Verify(h.Clone(), X, a.Commitment(), nil))

	out, err := cbor.Marshal(proof)
	require.NoError(t, err, "failed to marshal proof")
	proof2 := EmptyResponse(group)
	require.NoError(t, cbor.Unmarshal(out, proof2), "failed to unmarshal proof")
	out2, err := cbor.Marshal(proof2)
	require.NoError(t, err, "failed to marshal 2nd proof")
	proof3 := EmptyResponse(group)
	require.NoError(t, cbor.Unmarshal(out2, proof3), "failed to unmarshal 2nd proof")

	assert.True(t, proof3.Verify(h, X, a.Commitment(), nil))

}
func TestSchFail(t *testing.T) {
	hs := keystore.NewInMemoryKeystore()
	mgr := hash.NewHashManager(hs)
	h := mgr.NewHasher("test")

	group := curve.Secp256k1{}

	a := NewRandomness(rand.Reader, group, nil)
	x, X := group.NewScalar(), group.NewPoint()

	proof := a.Prove(h, X, x, nil)
	assert.False(t, proof.Verify(h, X, a.Commitment(), nil), "proof should not accept identity point")
}
