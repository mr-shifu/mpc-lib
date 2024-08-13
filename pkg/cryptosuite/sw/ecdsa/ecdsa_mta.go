package ecdsa

import (
	"github.com/cronokirby/saferith"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/paillier"
	zkaffg "github.com/mr-shifu/mpc-lib/core/zk/affg"
	"github.com/mr-shifu/mpc-lib/lib/mta"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
	cs_paillier "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillier"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/pedersen"
)

func (k ECDSAKey) NewMtAAffgProof(
	h hash.Hash,
	encoded *paillier.Ciphertext,
	selfPaillier cs_paillier.PaillierKey,
	partyPaillier cs_paillier.PaillierKey,
	ped pedersen.PedersenKey) (*saferith.Int, *paillier.Ciphertext, *paillier.Ciphertext, *zkaffg.Proof) {
	if k.Private() {
		return mta.ProveAffG(
			k.Group(),
			h,
			curve.MakeInt(k.priv),
			k.PublicKeyRaw(),
			encoded,
			selfPaillier.PublicKeyRaw(),
			partyPaillier.PublicKeyRaw(),
			ped.PublicKeyRaw(),
		)
	}
	return nil, nil, nil, nil
}
