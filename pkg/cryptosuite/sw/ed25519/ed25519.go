package ed25519

import (
	ed "filippo.io/edwards25519"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
	vssed25519 "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss-ed25519"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
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

	PublickeyPoint() *ed.Point

	// Multiply returns the result of multiplying the key by m.
	Multiply(m any) Ed25519

	Add(c any) (*ed.Scalar, error)

	// MultiplyAdd returns the result of multiplying the key by m and adding c.
	MultiplyAdd(m any, c any) *ed.Scalar

	NewScnorrProof(h hash.Hash) (*Proof, error)

	VerifySchnorrProof(h hash.Hash, proof *Proof) (bool, error)

	// FromBytes creates a new Ed25519 key from a byte representation.
	FromBytes(data []byte) error
}

type Ed25519KeyManager interface {
	// GenerateKey generates a new Ed25519 key pair.
	GenerateKey(opts keyopts.Options) (Ed25519, error)

	// Import imports a Ed25519 key from its byte representation.
	ImportKey(raw interface{}, opts keyopts.Options) (Ed25519, error)

	// GetKey returns a Ed25519 key by its SKI.
	GetKey(opts keyopts.Options) (Ed25519, error)

	SumKeys(optsList ...keyopts.Options) (Ed25519, error) 

	NewSchnorrProof(h hash.Hash, opts keyopts.Options) (*Proof, error)

	ImportSchnorrProof(pb []byte, opts keyopts.Options) error

	VerifySchnorrProof(h hash.Hash, opts keyopts.Options) (bool, error)

	GenerateVss(degree int, opts keyopts.Options) (vssed25519.VssKey, error)

	ImportVss(key interface{}, opts keyopts.Options) error

	GetVss(opts keyopts.Options) (vssed25519.VssKey, error)
}
