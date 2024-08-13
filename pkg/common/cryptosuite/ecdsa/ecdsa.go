package ecdsa

import (
	"github.com/cronokirby/saferith"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	paillier_core "github.com/mr-shifu/mpc-lib/core/paillier"
	zkaffg "github.com/mr-shifu/mpc-lib/core/zk/affg"
	zkenc "github.com/mr-shifu/mpc-lib/core/zk/enc"
	zklogstar "github.com/mr-shifu/mpc-lib/core/zk/logstar"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	pek "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillierencodedkey"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillier"
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

	Mul(c curve.Scalar) curve.Scalar

	AddKeys(keys ...ECDSAKey) curve.Scalar

	CloneByMultiplier(c curve.Scalar) ECDSAKey

	CloneByKeyMultiplier(km ECDSAKey, c curve.Scalar) ECDSAKey

	Commit(m curve.Scalar, c curve.Scalar) curve.Scalar

	CommitByKey(km ECDSAKey, c curve.Scalar) curve.Scalar

	NewSchnorrCommitment() (curve.Point, error)

	ImportSchnorrCommitment(commitment curve.Point) error

	GenerateSchnorrProof(h hash.Hash) (curve.Scalar, error)

	VerifySchnorrProof(h hash.Hash, proof curve.Scalar) (bool, error)

	SchnorrCommitment() (curve.Point, error)

	SchnorrProof() (curve.Scalar, error)

	GenerateVSSSecrets(degree int, opts keyopts.Options) error

	// ImportVSSSecrets(k vss.VssKey, opts keyopts.Options) error

	VSS(opts keyopts.Options) (vss.VssKey, error)

	EncodeByPaillier(pk paillier.PaillierKey) (pek.PaillierEncodedKey, error)

	NewZKEncProof(h hash.Hash, pek pek.PaillierEncodedKey, pk paillier.PaillierKey, ped pedersen.PedersenKey) (*zkenc.Proof, error)

	NewZKLogstarProof(
		h hash.Hash,
		pek pek.PaillierEncodedKey,
		C *paillier_core.Ciphertext,
		X curve.Point,
		G curve.Point,
		prover paillier.PaillierKey,
		ped pedersen.PedersenKey) (*zklogstar.Proof, error)

	NewMtAAffgProof(
		h hash.Hash,
		encoded *paillier_core.Ciphertext,
		selfPaillier paillier.PaillierKey,
		partyPaillier paillier.PaillierKey,
		ped pedersen.PedersenKey,
	) (*saferith.Int, *paillier_core.Ciphertext, *paillier_core.Ciphertext, *zkaffg.Proof)
}

type ECDSAKeyManager interface {
	NewKey(priv curve.Scalar, pub curve.Point, group curve.Curve) ECDSAKey

	// GenerateKey generates a new ECDSA key pair.
	GenerateKey(opts keyopts.Options) (ECDSAKey, error)

	// Import imports a ECDSA key from its byte representation.
	ImportKey(raw interface{}, opts keyopts.Options) (ECDSAKey, error)

	// GetKey returns a ECDSA key by its SKI.
	GetKey(opts keyopts.Options) (ECDSAKey, error)
}
