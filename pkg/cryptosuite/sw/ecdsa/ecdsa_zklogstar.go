package ecdsa

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	core_paillier "github.com/mr-shifu/mpc-lib/core/paillier"
	zklogstar "github.com/mr-shifu/mpc-lib/core/zk/logstar"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillier"
	pek "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillierencodedkey"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/pedersen"
)

func (k ECDSAKey) NewZKLogstarProof(
	h hash.Hash,
	pek pek.PaillierEncodedKey,
	C *core_paillier.Ciphertext,
	X curve.Point,
	G curve.Point,
	prover paillier.PaillierKey,
	ped pedersen.PedersenKey) (*zklogstar.Proof, error) {
	proof := zklogstar.NewProof(
		k.Group(),
		h,
		zklogstar.Public{
			C:      C,
			X:      X,
			G:      G,
			Prover: prover.PublicKeyRaw(),
			Aux:    ped.PublicKeyRaw(),
		}, zklogstar.Private{
			X:   curve.MakeInt(k.priv),
			Rho: pek.Nonce(),
		},
	)

	return proof, nil
}
