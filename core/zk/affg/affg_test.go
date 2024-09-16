package zkaffg

import (
	"crypto/rand"
	"testing"

	"github.com/cronokirby/saferith"
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

func TestAffG(t *testing.T) {
	hahs_keyopts := keyopts.NewInMemoryKeyOpts()
	hahs_vault := vault.NewInMemoryVault()
	hash_ks := keystore.NewInMemoryKeystore(hahs_vault, hahs_keyopts)
	hash_mgr := hash.NewHashManager(hash_ks)
	
	opts, err := keyopts.NewOptions().Set("id", "1", "partyid", "a")
	assert.NoError(t, err)
	h := hash_mgr.NewHasher("test", opts)

	group := curve.Secp256k1{}

	verifierPaillier := zk.VerifierPaillierPublic
	verifierPedersen := zk.Pedersen
	prover := zk.ProverPaillierPublic

	c := new(saferith.Int).SetUint64(12)
	C, _ := verifierPaillier.Enc(c)

	x := sample.IntervalL(rand.Reader)
	X := group.NewScalar().SetNat(x.Mod(group.Order())).ActOnBase()

	y := sample.IntervalLPrime(rand.Reader)
	Y, rhoY := prover.Enc(y)

	tmp := C.Clone().Mul(verifierPaillier, x)
	D, rho := verifierPaillier.Enc(y)
	D.Add(verifierPaillier, tmp)

	public := Public{
		Kv:       C,
		Dv:       D,
		Fp:       Y,
		Xp:       X,
		Prover:   prover,
		Verifier: verifierPaillier,
		Aux:      verifierPedersen,
	}
	private := Private{
		X: x,
		Y: y,
		S: rho,
		R: rhoY,
	}
	proof := NewProof(group, h.Clone(), public, private)
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
