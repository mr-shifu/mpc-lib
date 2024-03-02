package ecdsa

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/vss"
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

	NewSchnorrCommitment() (curve.Point, error)

	ImportSchnorrCommitment(commitment curve.Point) error

	GenerateSchnorrProof(h hash.Hash) (curve.Scalar, error)

	VerifySchnorrProof(h hash.Hash, proof curve.Scalar) (bool, error)

	SchnorrCommitment() (curve.Point, error)

	SchnorrProof() (curve.Scalar, error)

	GenerateVSSSecrets(degree int) error

	ImportVSSSecrets(exponents []byte) error

	VSS() (vss.VssKey, error)
}

type ECDSAKeyManager interface {
	// GenerateKey generates a new ECDSA key pair.
	GenerateKey() (ECDSAKey, error)

	// Import imports a ECDSA key from its byte representation.
	ImportKey(key ECDSAKey) (ECDSAKey, error)

	// GetKey returns a ECDSA key by its SKI.
	GetKey(ski []byte) (ECDSAKey, error)
}
