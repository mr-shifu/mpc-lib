package mta

import (
	"crypto/rand"

	"github.com/cronokirby/saferith"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
	"github.com/mr-shifu/mpc-lib/core/paillier"
	"github.com/mr-shifu/mpc-lib/core/pedersen"
	zkaffg "github.com/mr-shifu/mpc-lib/core/zk/affg"
	zkaffp "github.com/mr-shifu/mpc-lib/core/zk/affp"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
)

// ProveAffG returns the necessary messages for the receiver of the
// h is a hash function initialized with the sender's ID.
// - senderSecretShare = aᵢ
// - senderSecretSharePoint = Aᵢ = aᵢ⋅G
// - receiverEncryptedShare = Encⱼ(bⱼ)
// The elements returned are :
// - Beta = β
// - D = (aⱼ ⊙ Bᵢ) ⊕ encᵢ(- β, s)
// - F = encⱼ(-β, r)
// - Proof = zkaffg proof of correct encryption.
func ProveAffG(group curve.Curve, h hash.Hash,
	senderSecretShare *saferith.Int, senderSecretSharePoint curve.Point, receiverEncryptedShare *paillier.Ciphertext,
	sender *paillier.PublicKey, receiver *paillier.PublicKey, verifier *pedersen.Parameters) (Beta *saferith.Int, D, F *paillier.Ciphertext, Proof *zkaffg.Proof) {
	D, F, S, R, BetaNeg := newMta(senderSecretShare, receiverEncryptedShare, sender, receiver)
	Proof = zkaffg.NewProof(group, h, zkaffg.Public{
		Kv:       receiverEncryptedShare,
		Dv:       D,
		Fp:       F,
		Xp:       senderSecretSharePoint,
		Prover:   sender,
		Verifier: receiver,
		Aux:      verifier,
	}, zkaffg.Private{
		X: senderSecretShare,
		Y: BetaNeg,
		S: S,
		R: R,
	})
	Beta = BetaNeg.Neg(1)
	return
}

// ProveAffP generates a proof for the a specified verifier.
// This function is specified as to make clear which parameters must be input to zkaffg.
// h is a hash function initialized with the sender's ID.
// - senderSecretShare = aᵢ
// - senderSecretSharePoint = Aᵢ = Encᵢ(aᵢ)
// - receiverEncryptedShare = Encⱼ(bⱼ)
// The elements returned are :
// - Beta = β
// - D = (aⱼ ⊙ Bᵢ) ⊕ encᵢ(-β, s)
// - F = encⱼ(-β, r)
// - Proof = zkaffp proof of correct encryption.
func ProveAffP(
	group curve.Curve,
	h *hash.Hash,
	senderSecretShare *saferith.Int,
	senderEncryptedShare *paillier.Ciphertext,
	senderEncryptedShareNonce *saferith.Nat,
	receiverEncryptedShare *paillier.Ciphertext,
	sender *paillier.PublicKey,
	receiver *paillier.PublicKey,
	verifier *pedersen.Parameters) (Beta *saferith.Int, D, F *paillier.Ciphertext, Proof *zkaffp.Proof) {
	D, F, S, R, BetaNeg := newMta(senderSecretShare, receiverEncryptedShare, sender, receiver)
	Proof = zkaffp.NewProof(group, h, zkaffp.Public{
		Kv:       receiverEncryptedShare,
		Dv:       D,
		Fp:       F,
		Xp:       senderEncryptedShare,
		Prover:   sender,
		Verifier: receiver,
		Aux:      verifier,
	}, zkaffp.Private{
		X:  senderSecretShare,
		Y:  BetaNeg,
		S:  S,
		Rx: senderEncryptedShareNonce,
		R:  R,
	})
	Beta = BetaNeg.Neg(1)

	return
}

func newMta(
	senderSecretShare *saferith.Int,
	receiverEncryptedShare *paillier.Ciphertext,
	sender *paillier.PublicKey,
	receiver *paillier.PublicKey) (D, F *paillier.Ciphertext, S, R *saferith.Nat, BetaNeg *saferith.Int) {
	BetaNeg = sample.IntervalLPrime(rand.Reader)

	F, R = sender.Enc(BetaNeg) // F = encᵢ(-β, r)

	D, S = receiver.Enc(BetaNeg)
	tmp := receiverEncryptedShare.Clone().Mul(receiver, senderSecretShare) // tmp = aᵢ ⊙ Bⱼ
	D.Add(receiver, tmp)                                                   // D = encⱼ(-β;s) ⊕ (aᵢ ⊙ Bⱼ) = encⱼ(aᵢ•bⱼ-β)

	return
}
