package zkenc

import (
	"crypto/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
	"github.com/mr-shifu/mpc-lib/core/zk"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	"github.com/mr-shifu/mpc-lib/pkg/keystore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnc(t *testing.T) {
	hs := keystore.NewInMemoryKeystore()
	mgr := hash.NewHashManager(hs)
	h := mgr.NewHasher("test")

	group := curve.Secp256k1{}

	verifier := zk.Pedersen
	prover := zk.ProverPaillierPublic

	k := sample.IntervalL(rand.Reader)
	K, rho := prover.Enc(k)
	public := Public{
		K:      K,
		Prover: prover,
		Aux:    verifier,
	}

	proof := NewProof(group, h.Clone(), public, Private{
		K:   k,
		Rho: rho,
	})
	assert.True(t, proof.Verify(group, h.Clone(), public))

	out, err := cbor.Marshal(proof)
	require.NoError(t, err, "failed to marshal proof")
	proof2 := &Proof{}
	require.NoError(t, cbor.Unmarshal(out, proof2), "failed to unmarshal proof")
	out2, err := cbor.Marshal(proof2)
	require.NoError(t, err, "failed to marshal 2nd proof")
	proof3 := &Proof{}
	require.NoError(t, cbor.Unmarshal(out2, proof3), "failed to unmarshal 2nd proof")

	assert.True(t, proof3.Verify(group, h.Clone(), public))
}
