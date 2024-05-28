package ed25519

import (
	ed "filippo.io/edwards25519"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
)

type Ed25519 interface {
	// Bytes returns the byte representation of the key.
	Bytes() ([]byte, error)

	// SKI returns the serialized key identifier.
	SKI() []byte

	// Private returns true if the key is private.
	Private() bool

	// PublicKey returns the corresponding public key part of ECDSA Key.
	PublicKey() Ed25519

	// Multiply returns the result of multiplying the key by m.
	Multiply(m *ed.Scalar) *ed.Scalar

	// MultiplyAdd returns the result of multiplying the key by m and adding c.
	MultiplyAdd(m *ed.Scalar, c *ed.Scalar) *ed.Scalar

	NewScnorrProof(h hash.Hash) (*Proof, error)

	VerifySchnorrProof(h hash.Hash, proof *Proof) (bool, error)

	// FromBytes creates a new Ed25519 key from a byte representation.
	FromBytes(data []byte) error
}

type Ed25519KeyManager interface {
	NewKey(priv ed.Scalar, pub ed.Point) Ed25519

	// GenerateKey generates a new Ed25519 key pair.
	GenerateKey(opts keyopts.Options) (Ed25519, error)

	// Import imports a Ed25519 key from its byte representation.
	ImportKey(raw interface{}, opts keyopts.Options) (Ed25519, error)

	// GetKey returns a Ed25519 key by its SKI.
	GetKey(opts keyopts.Options) (Ed25519, error)

	NewSchnorrProof(h hash.Hash, opts keyopts.Options) (*Proof, error)

	ImportSchnorrProof(pb []byte, opts keyopts.Options) error

	VerifySchnorrProof(h hash.Hash, opts keyopts.Options) (bool, error)
}
