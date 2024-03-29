package ecdsa

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	zkenc "github.com/mr-shifu/mpc-lib/core/zk/enc"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/paillier"
	comm_pek "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/paillierencodedkey"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/pedersen"
)

func (k ECDSAKey) NewZKEncProof(h hash.Hash, pek comm_pek.PaillierEncodedKey, pk paillier.PaillierKey, ped pedersen.PedersenKey) (*zkenc.Proof, error) {
	proof := zkenc.NewProof(
		k.Group(),
		h,
		zkenc.Public{
			K:      pek.Encoded(),
			Prover: pk.PublicKeyRaw(),
			Aux:    ped.PublicKeyRaw(),
		}, zkenc.Private{
			K:   curve.MakeInt(k.priv),
			Rho: pek.Nonce(),
		},
	)

	return proof, nil
}
