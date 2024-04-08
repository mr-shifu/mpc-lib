package elgamal

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
)

type ElgamalKey interface {
	// Bytes returns the byte representation of the key.
	Bytes() ([]byte, error)

	// SKI returns the serialized key identifier.
	SKI() []byte

	// Private returns true if the key is private.
	Private() bool

	// PublicKey returns the corresponding public key part of Elgamal Key.
	PublicKey() ElgamalKey

	PublicKeyRaw() curve.Point

	// Encrypt returns the encryption of `message` as ciphertext and nonce.
	Encrypt(message curve.Scalar) ([]byte, curve.Scalar, error)
}

type ElgamalKeyManager interface {
	// GenerateKey generates a new Elgamal key pair.
	GenerateKey(opts keyopts.Options) (ElgamalKey, error)

	// Import imports a Elgamal key from its byte representation.
	ImportKey(data interface{}, opts keyopts.Options) (ElgamalKey, error)

	// GetKey returns a Elgamal key by its SKI.
	GetKey(pts keyopts.Options) (ElgamalKey, error)

	// Encrypt returns the encryption of `message` as ciphertext and nonce.
	Encrypt(message curve.Scalar, opts keyopts.Options) ([]byte, curve.Scalar, error)
}
