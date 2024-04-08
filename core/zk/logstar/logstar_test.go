package zklogstar

import (
	"crypto/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
	"github.com/mr-shifu/mpc-lib/core/zk"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogStar(t *testing.T) {
	hahs_keyopts := keyopts.NewInMemoryKeyOpts()
	hahs_vault := vault.NewInMemoryVault()
	hash_ks := keystore.NewInMemoryKeystore(hahs_vault, hahs_keyopts)
	hash_mgr := hash.NewHashManager(hash_ks)

	opts := keyopts.Options{}
	opts.Set("id", "1", "partyid", "a")
	h := hash_mgr.NewHasher("test", opts)

	group := curve.Secp256k1{}

	verifier := zk.Pedersen
	prover := zk.ProverPaillierPublic

	G := sample.Scalar(rand.Reader, group).ActOnBase()

	x := sample.IntervalL(rand.Reader)
	C, rho := prover.Enc(x)
	X := group.NewScalar().SetNat(x.Mod(group.Order())).Act(G)
	public := Public{
		C:      C,
		X:      X,
		G:      G,
		Prover: prover,
		Aux:    verifier,
	}

	proof := NewProof(group, h.Clone(), public, Private{
		X:   x,
		Rho: rho,
	})
	assert.True(t, proof.Verify(h.Clone(), public))

	out, err := cbor.Marshal(proof)
	require.NoError(t, err, "failed to marshal proof")
	proof2 := Empty(group)
	require.NoError(t, cbor.Unmarshal(out, proof2), "failed to unmarshal proof")
	out2, err := cbor.Marshal(proof2)
	require.NoError(t, err, "failed to marshal 2nd proof")
	proof3 := Empty(group)
	require.NoError(t, cbor.Unmarshal(out2, proof3), "failed to unmarshal 2nd proof")

	assert.True(t, proof3.Verify(h.Clone(), public))
}
