package ecdsa

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
)

func (key ECDSAKey) NewSchnorrCommitment() (curve.Point, error) {
	return key.zks.NewCommitment(key.group)
}

func (key ECDSAKey) ImportSchnorrCommitment(commitment curve.Point) error {
	return key.zks.ImportCommitment(commitment, key.group)
}

func (key ECDSAKey) GenerateSchnorrProof(hash hash.Hash) (curve.Scalar, error) {
	return key.zks.Prove(hash, key.priv, key.pub)
}

func (key ECDSAKey) VerifySchnorrProof(hash hash.Hash, proof curve.Scalar) (bool, error) {
	return key.zks.Verify(hash, key.pub, proof)
}

func (key ECDSAKey) SchnorrCommitment() (curve.Point, error) {
	return key.zks.Commitment()
}

func (key ECDSAKey) SchnorrProof() (curve.Scalar, error) {
	return key.zks.Proof()
}
