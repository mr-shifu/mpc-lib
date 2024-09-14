package vssed25519

import (
	"testing"

	"github.com/mr-shifu/mpc-lib/core/math/polynomial-ed25519"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/vault"
	"github.com/stretchr/testify/assert"
)

func geVsstKeyManager() *VssKeyManagerImpl {
	vss_keyopts := keyopts.NewInMemoryKeyOpts()
	vss_vault := vault.NewInMemoryVault()
	vss_ks := keystore.NewInMemoryKeystore(vss_vault, vss_keyopts)
	return NewVssKeyManager(vss_ks)
}

func TestVssEd25519VssKeyManager(t *testing.T) {
	mgr1 := geVsstKeyManager()
	mgr2 := geVsstKeyManager()

	constant, err := sample.Ed25519Scalar(nil)
	assert.NoError(t, err)

	degree := 5

	// Test Case 1: GenerateSecrets
	opts, err := keyopts.NewOptions().Set("id", "1", "partyid", "a")
	assert.NoError(t, err)
	vss1, err := mgr1.GenerateSecrets(constant, degree, opts)
	assert.NoError(t, err)
	assert.NotNil(t, vss1)

	// Test Case 2: ImportSecrets
	vss1Bytes, err := vss1.Bytes()
	assert.NoError(t, err)
	vss2, err := mgr2.ImportSecrets(vss1Bytes, opts)
	assert.NoError(t, err)
	assert.NotNil(t, vss2)
	assert.Equal(t, vss1.SKI(), vss2.SKI())

	// Test Case 3: GetSecrets
	vss3, err := mgr1.GetSecrets(opts)
	assert.NoError(t, err)
	assert.NotNil(t, vss3)

	vss4, err := mgr2.GetSecrets(opts)
	assert.NoError(t, err)
	assert.NotNil(t, vss4)

	assert.Equal(t, vss1.SKI(), vss3.SKI())
}

func TestVssEd25519VssKeyManager_Evaluate(t *testing.T) {
	mgr1 := geVsstKeyManager()

	constant, err := sample.Ed25519Scalar(nil)
	assert.NoError(t, err)

	degree := 5

	opts, err := keyopts.NewOptions().Set("id", "1", "partyid", "a")
	assert.NoError(t, err)
	vss1, err := mgr1.GenerateSecrets(constant, degree, opts)
	assert.NoError(t, err)
	assert.NotNil(t, vss1)

	// Test Case 1: Evaluate
	x, err := sample.Ed25519Scalar(nil)
	assert.NoError(t, err)

	v, err := vss1.Evaluate(x)
	assert.NoError(t, err)

	v1, err := mgr1.Evaluate(x, opts)
	assert.NoError(t, err)
	assert.NotNil(t, v1)
	assert.Equal(t, v, v1)

	// Test Case 2: EvaluateExponent
	V, err := vss1.EvaluateByExponents(x)
	assert.NoError(t, err)

	V1, err := vss1.EvaluateByExponents(x)
	assert.NoError(t, err)
	assert.NotNil(t, V1)
	assert.Equal(t, V, V1)

	// Test Case 3: Evaluate with invalid partyid
	opts.Set("id", "1", "partyid", "b")
	_, err = mgr1.Evaluate(x, opts)
	assert.Error(t, err)
}

func TestVssEd25519VssKeyManager_SumExponents(t *testing.T) {
	mgr1 := geVsstKeyManager()

	// generate secrets
	s1, err := sample.Ed25519Scalar(nil)
	assert.NoError(t, err)
	s2, err := sample.Ed25519Scalar(nil)
	assert.NoError(t, err)
	s3, err := sample.Ed25519Scalar(nil)
	assert.NoError(t, err)

	degree := 5

	// generate Vss for secrets
	opts1, err := keyopts.NewOptions().Set("id", "1", "partyid", "a")
	assert.NoError(t, err)
	vss1, err := mgr1.GenerateSecrets(s1, degree, opts1)
	assert.NoError(t, err)

	opts2, err := keyopts.NewOptions().Set("id", "1", "partyid", "b")
	assert.NoError(t, err)
	vss2, err := mgr1.GenerateSecrets(s2, degree, opts2)
	assert.NoError(t, err)

	opts3, err := keyopts.NewOptions().Set("id", "1", "partyid", "c")
	assert.NoError(t, err)
	vss3, err := mgr1.GenerateSecrets(s3, degree, opts3)
	assert.NoError(t, err)

	vss, err := new(polynomial.Polynomial).Sum([]*polynomial.Polynomial{vss1.(*VssKeyImpl).poly, vss2.(*VssKeyImpl).poly, vss3.(*VssKeyImpl).poly})
	assert.NoError(t, err)

	// Test Case 1: SumExponents
	sum, err := mgr1.SumExponents(opts1, opts2, opts3)
	assert.NoError(t, err)
	assert.NotNil(t, vss)

	sum_exp, err := sum.ExponentsRaw()
	assert.NoError(t, err)
	assert.Equal(t, 1, vss.Constant().Equal(sum_exp.Constant()))
}
