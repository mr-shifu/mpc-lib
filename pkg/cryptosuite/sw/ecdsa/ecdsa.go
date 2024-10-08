package ecdsa

import (
	"github.com/cronokirby/saferith"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	paillier_core "github.com/mr-shifu/mpc-lib/core/paillier"
	zkaffg "github.com/mr-shifu/mpc-lib/core/zk/affg"
	zkenc "github.com/mr-shifu/mpc-lib/core/zk/enc"
	zklogstar "github.com/mr-shifu/mpc-lib/core/zk/logstar"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillier"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillierencodedkey"
	pek "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillierencodedkey"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/pedersen"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss"
)

type ECDSAKey interface {
	// Bytes returns the byte representation of the key.
	Bytes() ([]byte, error)

	// SKI returns the serialized key identifier.
	SKI() []byte

	// Private returns true if the key is private.
	Private() bool

	// PublicKey returns the corresponding public key part of ECDSA Key.
	PublicKey() ECDSAKey

	// Group returns the curve group of the key.
	Group() curve.Curve

	// PublicKeyRaw returns the raw public key.
	PublicKeyRaw() curve.Point

	Act(g curve.Point, inv bool) curve.Point
}

type ECDSAKeyManager interface {
	// GenerateKey generates a new ECDSA key pair.
	GenerateKey(opts keyopts.Options) (ECDSAKey, error)

	// Import imports a ECDSA key from its byte representation.
	ImportKey(raw interface{}, opts keyopts.Options) (ECDSAKey, error)

	// GetKey returns a ECDSA key by its SKI.
	GetKey(opts keyopts.Options) (ECDSAKey, error)

	CloneByMultiplier(c curve.Scalar, opts keyopts.Options) (ECDSAKey, error)

	CloneByKeyMultiplier(km ECDSAKey, c curve.Scalar, opts keyopts.Options) (ECDSAKey, error)

	Act(g curve.Point, inv bool, opts keyopts.Options) (curve.Point, error)

	Mul(c curve.Scalar, opts keyopts.Options) (curve.Scalar, error)

	SumKeys(optsList ...keyopts.Options) (ECDSAKey, error)

	Commit(m curve.Scalar, c curve.Scalar, opts keyopts.Options) (curve.Scalar, error)

	CommitByKey(km ECDSAKey, c curve.Scalar, opts keyopts.Options) (curve.Scalar, error)

	GenerateSchnorrCommitment(h hash.Hash, opts keyopts.Options) (*Proof, error)
	GenerateSchnorrResponse(h hash.Hash, opts keyopts.Options) (*Proof, error)
	VerifySchnorrProof(h hash.Hash, opts keyopts.Options) (bool, error)
	ImportSchnorrCommitment(cmt_byte []byte, opts keyopts.Options) error
	ImportSchnorrProofResponse(zb []byte, opts keyopts.Options) error
	GetSchnorrProof(opts keyopts.Options) (*Proof, error)

	NewZKEncProof(h hash.Hash, pek pek.PaillierEncodedKey, pk paillier.PaillierKey, ped pedersen.PedersenKey, opts keyopts.Options) (*zkenc.Proof, error)

	NewZKLogstarProof(
		h hash.Hash,
		pek pek.PaillierEncodedKey,
		C *paillier_core.Ciphertext,
		X curve.Point,
		G curve.Point,
		prover paillier.PaillierKey,
		ped pedersen.PedersenKey,
		opts keyopts.Options) (*zklogstar.Proof, error)

	NewMtAAffgProof(
		h hash.Hash,
		encoded *paillier_core.Ciphertext,
		selfPaillier paillier.PaillierKey,
		partyPaillier paillier.PaillierKey,
		ped pedersen.PedersenKey,
		opts keyopts.Options) (*saferith.Int, *paillier_core.Ciphertext, *paillier_core.Ciphertext, *zkaffg.Proof, error)

	EncodeByPaillier(pk paillier.PaillierKey, opts keyopts.Options) (paillierencodedkey.PaillierEncodedKey, error)

	GenerateVss(degree int, opts keyopts.Options) (vss.VssKey, error)
	ImportVss(key interface{}, opts keyopts.Options) error
	GetVss(opts keyopts.Options) (vss.VssKey, error)
}
